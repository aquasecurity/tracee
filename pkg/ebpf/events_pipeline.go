package ebpf

import (
	"context"
	"encoding/binary"
	"fmt"
	"strconv"
	"sync"
	"unsafe"

	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/policy"
	"github.com/aquasecurity/tracee/pkg/signatures/engine"
	traceetime "github.com/aquasecurity/tracee/pkg/time"
	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/aquasecurity/tracee/types/trace"
)

// Max depth of each stack trace to track (MAX_STACK_DETPH in eBPF code)
const maxStackDepth int = 20

// Matches 'NO_SYSCALL' in eBPF code
const noSyscall int32 = -1

// handleEvents is the main pipeline of tracee. It receives events from the perf buffer
// and passes them through a series of stages, each stage is a goroutine that performs a
// specific task on the event. The pipeline is started in a separate goroutine.
func (t *Tracee) handleEvents(ctx context.Context, initialized chan<- struct{}) {
	logger.Debugw("Starting handleEvents goroutine")
	defer logger.Debugw("Stopped handleEvents goroutine")

	var errcList []<-chan error

	// Decode stage: events are read from the perf buffer and decoded into trace.Event type.

	eventsChan, errc := t.decodeEvents(ctx, t.eventsChannel)
	t.stats.Channels["decode"] = eventsChan
	errcList = append(errcList, errc)

	// Sort stage: events go through a sorting function.

	if t.config.Output.EventsSorting {
		eventsChan, errc = t.eventsSorter.StartPipeline(ctx, eventsChan, t.config.BlobPerfBufferSize)
		t.stats.Channels["sort"] = eventsChan
		errcList = append(errcList, errc)
	}

	// Process events stage: events go through a processing functions.

	eventsChan, errc = t.processEvents(ctx, eventsChan)
	t.stats.Channels["process"] = eventsChan
	errcList = append(errcList, errc)

	// Enrichment stage: container events are enriched with additional runtime data.

	if !t.config.NoContainersEnrich { // TODO: remove safe-guard soon.
		eventsChan, errc = t.enrichContainerEvents(ctx, eventsChan)
		t.stats.Channels["enrich"] = eventsChan
		errcList = append(errcList, errc)
	}

	// Derive events stage: events go through a derivation function.

	eventsChan, errc = t.deriveEvents(ctx, eventsChan)
	t.stats.Channels["derive"] = eventsChan
	errcList = append(errcList, errc)

	// Engine events stage: events go through the signatures engine for detection.

	if t.config.EngineConfig.Mode == engine.ModeSingleBinary {
		eventsChan, errc = t.engineEvents(ctx, eventsChan)
		t.stats.Channels["engine"] = eventsChan
		errcList = append(errcList, errc)
	}

	// Sink pipeline stage: events go through printers.

	errc = t.sinkEvents(ctx, eventsChan)
	t.stats.Channels["sink"] = eventsChan
	errcList = append(errcList, errc)

	initialized <- struct{}{}

	// Pipeline started. Waiting for pipeline to complete

	if err := t.WaitForPipeline(errcList...); err != nil {
		logger.Errorw("Pipeline", "error", err)
	}
}

// decodeEvents is the event decoding pipeline stage. For each received event, it goes
// through a decoding function that will decode the event from its raw format into a
// trace.Event type.
func (t *Tracee) decodeEvents(ctx context.Context, sourceChan chan []byte) (<-chan *trace.Event, <-chan error) {
	out := make(chan *trace.Event, t.config.PipelineChannelSize)
	errc := make(chan error, 1)

	// Create local decoder pool for this pipeline stage
	decoderPool := &sync.Pool{
		New: func() interface{} {
			return bufferdecoder.New(nil, t.dataTypeDecoder)
		},
	}

	go func() {
		defer close(out)
		defer close(errc)
		for dataRaw := range sourceChan {
			// Get decoder from local pool and reset it with the provided buffer
			decoderValue := decoderPool.Get()
			ebpfMsgDecoder, ok := decoderValue.(*bufferdecoder.EbpfDecoder)
			if !ok {
				t.handleError(errfmt.Errorf("failed to get decoder from pool: unexpected type %T", decoderValue))
				continue
			}
			ebpfMsgDecoder.SetBuffer(dataRaw)

			var eCtx bufferdecoder.EventContext
			if err := ebpfMsgDecoder.DecodeContext(&eCtx); err != nil {
				t.handleError(err)
				decoderPool.Put(ebpfMsgDecoder)
				continue
			}
			var argnum uint8
			if err := ebpfMsgDecoder.DecodeUint8(&argnum); err != nil {
				t.handleError(err)
				decoderPool.Put(ebpfMsgDecoder)
				continue
			}
			eventId := events.ID(eCtx.EventID)
			eventDefinition := events.Core.GetDefinitionByID(eventId)
			if eventDefinition.NotValid() {
				t.handleError(errfmt.Errorf("failed to get configuration of event %d", eventId))
				decoderPool.Put(ebpfMsgDecoder)
				continue
			}

			evtFields := eventDefinition.GetFields()
			evtName := eventDefinition.GetName()
			args := make([]trace.Argument, len(evtFields))
			err := ebpfMsgDecoder.DecodeArguments(args, int(argnum), evtFields, evtName, eventId)
			if err != nil {
				t.handleError(err)
				decoderPool.Put(ebpfMsgDecoder)
				continue
			}

			// Add stack trace if needed
			var stackAddresses []uint64
			if t.config.Output.StackAddresses {
				stackAddresses = t.getStackAddresses(eCtx.StackID)
			}

			_, containerInfo := t.containers.GetCgroupInfo(eCtx.CgroupID)

			commStr := string(utils.TrimTrailingNUL(eCtx.Comm[:]))       // clean potential trailing null
			utsNameStr := string(utils.TrimTrailingNUL(eCtx.UtsName[:])) // clean potential trailing null

			flags := parseContextFlags(containerInfo.ContainerId, eCtx.Flags)

			// Optimize syscall lookup - reuse eventDefinition if possible
			syscall := ""
			if eCtx.Syscall != noSyscall {
				// The syscall ID returned from eBPF is actually the event ID representing that syscall.
				// For 64-bit processes, the event ID is the same as the syscall ID.
				// For 32-bit (compat) processes, the syscall ID gets translated in eBPF to the event ID of its
				// 64-bit counterpart, or if it's a 32-bit exclusive syscall, to the event ID corresponding to it.
				id := events.ID(eCtx.Syscall)
				if id == eventId {
					// Reuse the already-fetched eventDefinition
					syscall = evtName
				} else {
					syscallDef := events.Core.GetDefinitionByID(id)
					if syscallDef.NotValid() {
						logger.Debugw(
							fmt.Sprintf("Event %s with an invalid syscall id %d", evtName, id),
							"Comm", commStr,
							"UtsName", utsNameStr,
							"EventContext", eCtx,
						)
					}
					syscall = syscallDef.GetName()
				}
			}

			// get an event pointer from the pool
			evt, ok := t.eventsPool.Get().(*trace.Event)
			if !ok {
				t.handleError(errfmt.Errorf("failed to get event from pool"))
				decoderPool.Put(ebpfMsgDecoder)
				continue
			}

			// populate all the fields of the event used in this stage, and reset the rest

			evt.Timestamp = int(traceetime.BootToEpochNS(eCtx.Ts))              // normalize time
			evt.ThreadStartTime = int(traceetime.BootToEpochNS(eCtx.StartTime)) // normalize time
			evt.ProcessorID = int(eCtx.ProcessorId)
			evt.ProcessID = int(eCtx.Pid)
			evt.ThreadID = int(eCtx.Tid)
			evt.ParentProcessID = int(eCtx.Ppid)
			evt.HostProcessID = int(eCtx.HostPid)
			evt.HostThreadID = int(eCtx.HostTid)
			evt.HostParentProcessID = int(eCtx.HostPpid)
			evt.UserID = int(eCtx.Uid)
			evt.MountNS = int(eCtx.MntID)
			evt.PIDNS = int(eCtx.PidID)
			evt.ProcessName = commStr
			evt.HostName = utsNameStr
			evt.CgroupID = uint(eCtx.CgroupID)
			evt.ContainerID = containerInfo.ContainerId
			evt.Container = trace.Container{
				ID:          containerInfo.ContainerId,
				ImageName:   containerInfo.Image,
				ImageDigest: containerInfo.ImageDigest,
				Name:        containerInfo.Name,
			}
			evt.Kubernetes = trace.Kubernetes{
				PodName:      containerInfo.Pod.Name,
				PodNamespace: containerInfo.Pod.Namespace,
				PodUID:       containerInfo.Pod.UID,
			}
			evt.EventID = int(eCtx.EventID)
			evt.EventName = evtName
			evt.RulesVersion = eCtx.RulesVersion
			// Convert eBPF single bitmap to bitmap array
			if eCtx.MatchedRules != 0 {
				evt.MatchedRulesKernel = []uint64{eCtx.MatchedRules}
			} else {
				evt.MatchedRulesKernel = []uint64{}
			}
			evt.MatchedRulesUser = []uint64{}
			evt.MatchedPolicies = []string{}
			evt.ArgsNum = int(argnum)
			evt.ReturnValue = int(eCtx.Retval)
			evt.Args = args
			evt.StackAddresses = stackAddresses
			evt.ContextFlags = flags
			evt.Syscall = syscall
			evt.Metadata = nil
			// compute hashes using normalized times
			evt.ThreadEntityId = utils.HashTaskID(eCtx.HostTid, uint64(evt.ThreadStartTime))
			if eCtx.HostTid == eCtx.HostPid && eCtx.StartTime == eCtx.LeaderStartTime {
				// If the thread is the leader (i.e., HostTid == HostPid and StartTime == LeaderStartTime),
				// then ProcessEntityId and ThreadEntityId are identical and can be shared.
				evt.ProcessEntityId = evt.ThreadEntityId
			} else {
				evt.ProcessEntityId = utils.HashTaskID(eCtx.HostPid, traceetime.BootToEpochNS(eCtx.LeaderStartTime))
			}
			evt.ParentEntityId = utils.HashTaskID(eCtx.HostPpid, traceetime.BootToEpochNS(eCtx.ParentStartTime))

			// TODO(unrelated): move this to process stage (why did it moved here in the first place?)
			if !t.matchRules(evt) {
				_ = t.stats.EventsFiltered.Increment()
				t.eventsPool.Put(evt)
				decoderPool.Put(ebpfMsgDecoder)
				continue
			}

			select {
			case out <- evt:
			case <-ctx.Done():
				decoderPool.Put(ebpfMsgDecoder)
				return
			}

			// Return decoder to pool for reuse
			decoderPool.Put(ebpfMsgDecoder)
		}
	}()
	return out, errc
}

// matchRules does the userland filtering (rule matching) for events. It iterates through all
// existing rules, that were set by the kernel in the event bitmap. Some of those rules might
// not match the event after userland filters are applied. In those cases, the rule bit is cleared
// (so the event is "filtered" for that rule). This may be called in different stages of the
// pipeline (decode, derive, engine).
func (t *Tracee) matchRules(event *trace.Event) bool {
	eventID := events.ID(event.EventID)

	// match scope filters for overflow rules that were not matched by the bpf code
	t.matchOverflowRules(event)

	// Create a copy of the kernel matched rules bitmap array to work with
	bitmap := make([]uint64, len(event.MatchedRulesKernel))
	copy(bitmap, event.MatchedRulesKernel)

	// Cache frequently accessed event fields
	eventUID := uint32(event.UserID)
	eventPID := uint32(event.HostProcessID)
	eventRetVal := int64(event.ReturnValue)

	// range through each userland filterable rule
	for _, rule := range t.policyManager.GetUserlandRules(eventID) {
		// Use proper bit index and bit offset for rules with ID > 64
		if !utils.HasBitInArray(bitmap, rule.ID) { // event does not match this rule
			continue
		}

		//
		// Do the userland filtering - ordered by efficiency (cheapest first)
		//

		// 1. UID/PID range checks (very fast)
		if rule.Policy.UIDFilter.Enabled() {
			if !rule.Policy.UIDFilter.InMinMaxRange(eventUID) {
				utils.ClearBitInArray(&bitmap, rule.ID)
				continue
			}
		}

		if rule.Policy.PIDFilter.Enabled() {
			//
			// The same happens for the global PID min/max range. Clear the rule bit if
			// the event PID is not in THIS rule PID min/max range.
			//
			if !rule.Policy.PIDFilter.InMinMaxRange(eventPID) {
				utils.ClearBitInArray(&bitmap, rule.ID)
				continue
			}
		}

		// 2. event return value filters (fast)
		if !rule.Data.RetFilter.Filter(eventRetVal) {
			utils.ClearBitInArray(&bitmap, rule.ID)
			continue
		}

		// 3. event scope filters (medium cost)
		if !rule.Data.ScopeFilter.Filter(*event) {
			utils.ClearBitInArray(&bitmap, rule.ID)
			continue
		}

		// 4. event data filters (potentially expensive)
		// TODO: remove PrintMemDump check once events params are introduced
		//       i.e. print_mem_dump.params.symbol_name=system:security_file_open
		// events.PrintMemDump bypass was added due to issue #2546
		// because it uses usermode applied filters as parameters for the event,
		// which occurs after filtering
		if eventID != events.PrintMemDump && !rule.Data.DataFilter.Filter(event.Args) {
			utils.ClearBitInArray(&bitmap, rule.ID)
			continue
		}

		// Early exit optimization: if bitmap array becomes empty, no need to continue
		if utils.IsBitmapArrayEmpty(bitmap) {
			break
		}
	}

	event.MatchedRulesUser = bitmap // store filtered bitmap to be used in sink stage

	return !utils.IsBitmapArrayEmpty(bitmap)
}

// matchOverflowRules applies scope filters for overflow rules using the same logic as eBPF filtering
func (t *Tracee) matchOverflowRules(event *trace.Event) {
	// Skip if event doesn't have overflow
	if !t.policyManager.HasOverflowRules(events.ID(event.EventID)) {
		return
	}

	// Create filter version key
	vKey := policy.FilterVersionKey{
		Version: event.RulesVersion,
		EventID: uint32(event.EventID),
	}

	// Get filter maps
	fMaps := t.policyManager.GetFilterMaps()
	if fMaps == nil {
		return
	}

	// Get extended scope filter configs to check which filters are enabled for overflow rules
	extendedConfig, ok := fMaps.ExtendedScopeFilterConfigs[events.ID(event.EventID)]
	if !ok {
		return
	}

	// Following eBPF logic: start with all overflow rules enabled (~0ULL equivalent)
	// We work only on overflow bitmaps (index 1 and above)
	overflowStartIndex := 1
	maxBitmapIndex := len(event.MatchedRulesKernel)

	// Determine how many overflow bitmaps we need to work with
	for _, enabledBitmaps := range [][]uint64{
		extendedConfig.CommFilterEnabled,
		extendedConfig.UIDFilterEnabled,
		extendedConfig.PIDFilterEnabled,
		extendedConfig.MntNsFilterEnabled,
		extendedConfig.PidNsFilterEnabled,
		extendedConfig.UtsNsFilterEnabled,
		extendedConfig.CgroupIdFilterEnabled,
		extendedConfig.ContFilterEnabled,
	} {
		if len(enabledBitmaps) > maxBitmapIndex {
			maxBitmapIndex = len(enabledBitmaps)
		}
	}

	// Ensure MatchedRulesKernel has enough space for overflow rules
	for len(event.MatchedRulesKernel) < maxBitmapIndex {
		event.MatchedRulesKernel = append(event.MatchedRulesKernel, 0)
	}

	// Initialize overflow bitmaps to all rules enabled (equivalent to res = ~0ULL in eBPF)
	for i := overflowStartIndex; i < maxBitmapIndex; i++ {
		event.MatchedRulesKernel[i] = ^uint64(0) // All bits set
	}

	// Apply each scope filter using the same logic as eBPF: res &= equality_filter_matches(...) | mask
	t.applyOverflowScopeFilter(event, fMaps.CommFilters[vKey], event.ProcessName, extendedConfig.CommFilterEnabled, extendedConfig.CommFilterMatchIfKeyMissing)
	t.applyOverflowScopeFilter(event, fMaps.UIDFilters[vKey], uint64(event.UserID), extendedConfig.UIDFilterEnabled, extendedConfig.UIDFilterMatchIfKeyMissing)
	t.applyOverflowScopeFilter(event, fMaps.PIDFilters[vKey], uint64(event.HostProcessID), extendedConfig.PIDFilterEnabled, extendedConfig.PIDFilterMatchIfKeyMissing)
	t.applyOverflowScopeFilter(event, fMaps.MntNsFilters[vKey], uint64(event.MountNS), extendedConfig.MntNsFilterEnabled, extendedConfig.MntNsFilterMatchIfKeyMissing)
	t.applyOverflowScopeFilter(event, fMaps.PidNsFilters[vKey], uint64(event.PIDNS), extendedConfig.PidNsFilterEnabled, extendedConfig.PidNsFilterMatchIfKeyMissing)
	t.applyOverflowScopeFilter(event, fMaps.UTSFilters[vKey], event.HostName, extendedConfig.UtsNsFilterEnabled, extendedConfig.UtsNsFilterMatchIfKeyMissing)
	t.applyOverflowScopeFilter(event, fMaps.CgroupFilters[vKey], uint64(event.CgroupID), extendedConfig.CgroupIdFilterEnabled, extendedConfig.CgroupIdFilterMatchIfKeyMissing)

	// Container filter: only apply if ContainerID is not empty
	if event.ContainerID != "" {
		t.applyOverflowScopeFilter(event, fMaps.ContainerFilters[vKey], event.ContainerID, extendedConfig.ContFilterEnabled, extendedConfig.ContFilterMatchIfKeyMissing)
	} else {
		// If no ContainerID, apply the mask logic for missing key behavior
		t.applyOverflowScopeFilterMissingKey(event, extendedConfig.ContFilterEnabled, extendedConfig.ContFilterMatchIfKeyMissing)
	}
}

// applyOverflowScopeFilter implements the same logic as equality_filter_matches in eBPF
// res &= equality_filter_matches(match_if_key_missing, filter_map, &key) | mask
func (t *Tracee) applyOverflowScopeFilter(event *trace.Event, filterMap interface{}, key interface{}, filterEnabled []uint64, matchIfKeyMissing []uint64) {
	overflowStartIndex := 1

	for i := overflowStartIndex; i < len(event.MatchedRulesKernel); i++ {
		// Get the mask for rules that don't have this filter enabled (equivalent to ~filter_enabled in eBPF)
		mask := ^uint64(0) // Default: all rules pass if filter not enabled
		if i < len(filterEnabled) {
			mask = ^filterEnabled[i]
		}

		// Get match_if_key_missing bitmap for this overflow bitmap
		var matchIfMissing uint64
		if i < len(matchIfKeyMissing) {
			matchIfMissing = matchIfKeyMissing[i]
		}

		// Implement equality_filter_matches logic
		equalsInRules := t.getEqualsInRulesForOverflow(filterMap, key, i)
		keyUsedInRules := t.getKeyUsedInRulesForOverflow(filterMap, key, i)

		// eBPF logic: equals_in_rules | (match_if_key_missing & ~key_used_in_rules)
		filterMatches := equalsInRules | (matchIfMissing & ^keyUsedInRules)

		// Apply filter: res &= equality_filter_matches(...) | mask
		event.MatchedRulesKernel[i] &= filterMatches | mask
	}
}

// applyOverflowScopeFilterMissingKey handles the case when a key is missing (e.g., empty ContainerID)
func (t *Tracee) applyOverflowScopeFilterMissingKey(event *trace.Event, filterEnabled []uint64, matchIfKeyMissing []uint64) {
	overflowStartIndex := 1

	for i := overflowStartIndex; i < len(event.MatchedRulesKernel); i++ {
		// Get the mask for rules that don't have this filter enabled
		mask := ^uint64(0)
		if i < len(filterEnabled) {
			mask = ^filterEnabled[i]
		}

		// Get match_if_key_missing bitmap
		var matchIfMissing uint64
		if i < len(matchIfKeyMissing) {
			matchIfMissing = matchIfKeyMissing[i]
		}

		// When key is missing: equals_in_rules = 0, key_used_in_rules = 0
		// So result is: 0 | (match_if_key_missing & ~0) = match_if_key_missing
		filterMatches := matchIfMissing

		// Apply filter: res &= filterMatches | mask
		event.MatchedRulesKernel[i] &= filterMatches | mask
	}
}

// getEqualsInRulesForOverflow extracts the equals_in_rules bitmap for overflow rules from filter maps
func (t *Tracee) getEqualsInRulesForOverflow(filterMap interface{}, key interface{}, bitmapIndex int) uint64 {
	if filterMap == nil {
		return 0
	}

	switch fm := filterMap.(type) {
	case map[uint64][]policy.RuleBitmap:
		if uint64Key, ok := key.(uint64); ok {
			if bitmaps, exists := fm[uint64Key]; exists && bitmapIndex < len(bitmaps) {
				return bitmaps[bitmapIndex].EqualsInRules
			}
		}
	case map[string][]policy.RuleBitmap:
		if stringKey, ok := key.(string); ok {
			if bitmaps, exists := fm[stringKey]; exists && bitmapIndex < len(bitmaps) {
				return bitmaps[bitmapIndex].EqualsInRules
			}
		}
	}

	return 0
}

// getKeyUsedInRulesForOverflow extracts the key_used_in_rules bitmap for overflow rules from filter maps
func (t *Tracee) getKeyUsedInRulesForOverflow(filterMap interface{}, key interface{}, bitmapIndex int) uint64 {
	if filterMap == nil {
		return 0
	}

	switch fm := filterMap.(type) {
	case map[uint64][]policy.RuleBitmap:
		if uint64Key, ok := key.(uint64); ok {
			if bitmaps, exists := fm[uint64Key]; exists && bitmapIndex < len(bitmaps) {
				return bitmaps[bitmapIndex].KeyUsedInRules
			}
		}
	case map[string][]policy.RuleBitmap:
		if stringKey, ok := key.(string); ok {
			if bitmaps, exists := fm[stringKey]; exists && bitmapIndex < len(bitmaps) {
				return bitmaps[bitmapIndex].KeyUsedInRules
			}
		}
	}

	return 0
}

func parseContextFlags(containerId string, flags uint32) trace.ContextFlags {
	const (
		contStartFlag = 1 << iota
		IsCompatFlag
	)

	var cflags trace.ContextFlags
	// Handle the edge case where containerStarted flag remains true despite an empty
	// containerId. See #3251 for more details.
	cflags.ContainerStarted = (containerId != "") && (flags&contStartFlag) != 0
	cflags.IsCompat = (flags & IsCompatFlag) != 0

	return cflags
}

// processEvents is the event processing pipeline stage. For each received event, it goes
// through all event processors and check if there is any internal processing needed for
// that event type.  It also clears rule bits for out-of-order container related events
// (after the processing logic). This stage also starts some logic that will be used by
// the processing logic in subsequent events.
func (t *Tracee) processEvents(ctx context.Context, in <-chan *trace.Event) (
	<-chan *trace.Event, <-chan error,
) {
	out := make(chan *trace.Event, t.config.PipelineChannelSize)
	errc := make(chan error, 1)

	// Some "informational" events are started here (TODO: API server?)
	t.invokeInitEvents(out)

	go func() {
		defer close(out)
		defer close(errc)

		for event := range in { // For each received event...
			if event == nil {
				continue // might happen during initialization (ctrl+c seg faults)
			}

			// Go through event processors if needed
			errs := t.processEvent(event)
			if len(errs) > 0 {
				for _, err := range errs {
					t.handleError(err)
				}
				t.eventsPool.Put(event)
				continue
			}

			// Get a bitmap with all rules containing container filters
			eventId := events.ID(event.EventID)
			containerFilteredRules := t.policyManager.GetContainerFilteredRulesBitmap(eventId)

			// Filter out events that don't have a container ID from all the rules that
			// have container filters. This will guarantee that any of those rules
			// won't get matched by this event. This situation might happen if the events
			// from a recently created container appear BEFORE the initial cgroup_mkdir of
			// that container root directory.  This could be solved by sorting the events
			// by a monotonic timestamp, for example, but sorting might not always be
			// enabled, so, in those cases, ignore the event IF the event is not a
			// cgroup_mkdir or cgroup_rmdir.

			if len(containerFilteredRules) > 0 && containerFilteredRules[0] > 0 && event.Container.ID == "" {
				// never skip cgroup_{mkdir,rmdir}: container_{create,remove} events need it
				if eventId == events.CgroupMkdir || eventId == events.CgroupRmdir {
					goto sendEvent
				}

				logger.Debugw("False container positive", "event.Timestamp", event.Timestamp,
					"eventId", eventId)

				// remove event from rules with container filters
				if len(event.MatchedRulesKernel) > 0 {
					utils.ClearBits(&event.MatchedRulesKernel[0], containerFilteredRules[0])
				}
				if len(event.MatchedRulesUser) > 0 {
					utils.ClearBits(&event.MatchedRulesUser[0], containerFilteredRules[0])
				}

				if utils.IsBitmapArrayEmpty(event.MatchedRulesKernel) {
					t.eventsPool.Put(event)
					continue
				}
			}

		sendEvent:
			select {
			case out <- event:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, errc
}

// deriveEVents is the event derivation pipeline stage. For each received event, it runs
// the event derivation logic, described in the derivation table, and send the derived
// events down the pipeline.
func (t *Tracee) deriveEvents(ctx context.Context, in <-chan *trace.Event) (
	<-chan *trace.Event, <-chan error,
) {
	out := make(chan *trace.Event, t.config.PipelineChannelSize)
	errc := make(chan error, 1)

	go func() {
		defer close(out)
		defer close(errc)

		for {
			select {
			case event := <-in:
				if event == nil {
					continue // might happen during initialization (ctrl+c seg faults)
				}

				// Derive events using original event pointer directly (no copying needed)
				// We derive before sending the event downstream to avoid race conditions
				derivatives, errors := t.eventDerivations.DeriveEvent(event)

				// Send original event down the pipeline
				out <- event

				// Capture base event info for derived event processing
				baseEventID := event.EventID
				baseEventMatchedRules := event.MatchedRulesUser

				for _, err := range errors {
					t.handleError(err)
				}

				for i := range derivatives {
					// Passing "derivative" variable here will make the ptr address always
					// be the same as the last item. This makes the printer to print 2 or
					// 3 times the last event, instead of printing all derived events
					// (when there are more than one).
					//
					// Nadav: Likely related to https://github.com/golang/go/issues/57969 (GOEXPERIMENT=loopvar).
					//        Let's keep an eye on that moving from experimental for these and similar cases in tracee.
					event := &derivatives[i]

					// Get matched rules for derived event based on base event matches
					event.MatchedRulesUser = t.policyManager.GetDerivedEventMatchedRules(
						events.ID(event.EventID), // derived event ID
						events.ID(baseEventID),   // base event ID
						baseEventMatchedRules,    // base event matched rules bitmap
					)
					// We need to update the kernel matched rules since it is used in matchedRules function
					event.MatchedRulesKernel = event.MatchedRulesUser

					// Skip events that dont work with filtering due to missing types
					// being handled (https://github.com/aquasecurity/tracee/issues/2486)
					switch events.ID(derivatives[i].EventID) {
					case events.SymbolsLoaded:
					case events.SharedObjectLoaded:
					case events.PrintMemDump:
					default:
						// Derived events might need filtering as well
						if !t.matchRules(event) {
							_ = t.stats.EventsFiltered.Increment()
							continue
						}
					}

					// Process derived events
					t.processEvent(event)
					out <- event
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	return out, errc
}

// sinkEvents is the event sink pipeline stage. For each received event, it goes through a
// series of printers that will print the event to the desired output. It also handles the
// event pool, returning the event to the pool after it is processed.
func (t *Tracee) sinkEvents(ctx context.Context, in <-chan *trace.Event) <-chan error {
	errc := make(chan error, 1)

	go func() {
		defer close(errc)

		for event := range in {
			if event == nil {
				continue // might happen during initialization (ctrl+c seg faults)
			}

			if !t.policyManager.IsEventEnabled(events.ID(event.EventID)) {
				// TODO: create metrics from dropped events
				t.eventsPool.Put(event)
				continue
			}

			// Only emit events requested by the user and matched by at least one rule.
			id := events.ID(event.EventID)
			event.MatchedPolicies = t.policyManager.GetMatchedRulesInfo(id, event.MatchedRulesUser)
			if len(event.MatchedPolicies) == 0 {
				t.eventsPool.Put(event)
				continue
			}

			// Parse arguments for output formatting if enabled.
			if t.config.Output.ParseArguments {
				err := t.parseArguments(event)
				if err != nil {
					t.handleError(err)
				}
			}

			// Send the event to the streams.
			select {
			case <-ctx.Done():
				return
			default:
				t.streamsManager.Publish(ctx, *event)
				_ = t.stats.EventCount.Increment()
				t.eventsPool.Put(event)
			}
		}
	}()

	return errc
}

// getStackAddresses returns the stack addresses for a given StackID
func (t *Tracee) getStackAddresses(stackID uint32) []uint64 {
	stackAddresses := make([]uint64, maxStackDepth)
	stackFrameSize := (strconv.IntSize / 8)

	// Lookup the StackID in the map
	// The ID could have aged out of the Map, as it only holds a finite number of
	// Stack IDs in it's Map
	var stackBytes []byte
	err := capabilities.GetInstance().EBPF(func() error {
		bytes, e := t.StackAddressesMap.GetValue(unsafe.Pointer(&stackID))
		if e == nil {
			stackBytes = bytes
		}
		return e
	})
	if err != nil {
		logger.Debugw("failed to get StackAddress", "error", err)
		return stackAddresses[0:0]
	}

	stackCounter := 0
	for i := 0; i < len(stackBytes); i += stackFrameSize {
		stackAddresses[stackCounter] = 0
		stackAddr := binary.LittleEndian.Uint64(stackBytes[i : i+stackFrameSize])
		if stackAddr == 0 {
			break
		}
		stackAddresses[stackCounter] = stackAddr
		stackCounter++
	}

	// Attempt to remove the ID from the map so we don't fill it up
	// But if this fails continue on
	err = capabilities.GetInstance().EBPF(func() error {
		return t.StackAddressesMap.DeleteKey(unsafe.Pointer(&stackID))
	})
	if err != nil {
		logger.Debugw("failed to delete stack address from eBPF map", "error", err)
	}

	return stackAddresses[0:stackCounter]
}

// WaitForPipeline waits for results from all error channels.
func (t *Tracee) WaitForPipeline(errs ...<-chan error) error {
	errc := MergeErrors(errs...)
	for err := range errc {
		t.handleError(err)
	}
	return nil
}

// MergeErrors merges multiple channels of errors (https://blog.golang.org/pipelines)
func MergeErrors(cs ...<-chan error) <-chan error {
	var wg sync.WaitGroup
	// We must ensure that the output channel has the capacity to hold as many errors as
	// there are error channels. This will ensure that it never blocks, even if
	// WaitForPipeline returns early.
	out := make(chan error, len(cs))

	output := func(c <-chan error) {
		for n := range c {
			out <- n
		}
		wg.Done()
	}
	wg.Add(len(cs))
	for _, c := range cs {
		go output(c)
	}

	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

func (t *Tracee) handleError(err error) {
	_ = t.stats.ErrorCount.Increment()
	logger.Errorw("Tracee encountered an error", "error", err)
}

// parseArguments parses the arguments of the event for display purposes.
// This converts raw arguments (e.g., syscall numbers, addresses) to human-readable
// format (e.g., syscall names, file paths). It uses the efficient slice-based parsing
// functions and modifies the event's Args slice in-place.
func (t *Tracee) parseArguments(e *trace.Event) error {
	if !t.config.Output.ParseArguments || len(e.Args) == 0 {
		return nil
	}

	// Parse arguments in-place using the efficient slice-based functions
	err := events.ParseArgsSlice(e.Args, e.EventID)
	if err != nil {
		return errfmt.WrapError(err)
	}

	if t.config.Output.ParseArgumentsFDs {
		err = events.ParseArgsFDsSlice(e.Args, uint64(e.Timestamp), t.FDArgPathMap)
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	return nil
}

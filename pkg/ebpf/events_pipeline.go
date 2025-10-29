package ebpf

import (
	"context"
	"encoding/binary"
	"fmt"
	"strconv"
	"sync"
	"unsafe"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/common/bitwise"
	"github.com/aquasecurity/tracee/common/capabilities"
	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/common/stringutil"
	"github.com/aquasecurity/tracee/common/timeutil"
	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/pkg/datastores/process"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/signatures/engine"
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

	// Detect events stage: events go through the detector engine for detection.

	eventsChan, errc = t.detectEvents(ctx, eventsChan)
	t.stats.Channels["detect"] = eventsChan
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
// PipelineEvent type.
func (t *Tracee) decodeEvents(ctx context.Context, sourceChan chan []byte) (<-chan *events.PipelineEvent, <-chan error) {
	out := make(chan *events.PipelineEvent, t.config.PipelineChannelSize)
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

			_, containerInfo := t.container.GetCgroupInfo(eCtx.CgroupID)

			commStr := string(stringutil.TrimTrailingNUL(eCtx.Comm[:]))       // clean potential trailing null
			utsNameStr := string(stringutil.TrimTrailingNUL(eCtx.UtsName[:])) // clean potential trailing null

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
			evt, ok := t.eventsPool.Get().(*events.PipelineEvent)
			if !ok {
				t.handleError(errfmt.Errorf("failed to get event from pool"))
				decoderPool.Put(ebpfMsgDecoder)
				continue
			}

			// Ensure the embedded Event pointer is initialized
			if evt.Event == nil {
				evt.Event = &trace.Event{}
			}

			// Reset internal fields for reuse
			evt.Reset()

			// populate all the fields of the event used in this stage, and reset the rest

			// Set pipeline-level metadata (normalized timestamps)
			evt.Timestamp = timeutil.BootToEpochNS(eCtx.Ts)
			evt.EventID = eCtx.EventID

			// Set trace.Event fields
			evt.Event.Timestamp = int(evt.Timestamp)                          // Keep trace.Event.Timestamp for backward compatibility
			evt.ThreadStartTime = int(timeutil.BootToEpochNS(eCtx.StartTime)) // normalize time
			evt.ProcessorID = int(eCtx.ProcessorId)
			evt.Event.EventID = int(evt.EventID) // Keep trace.Event.EventID in sync (int32 -> int)
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
			evt.EventName = evtName
			evt.PoliciesVersion = eCtx.PoliciesVersion
			evt.MatchedPoliciesKernel = eCtx.MatchedPolicies
			evt.MatchedPoliciesUser = 0
			evt.MatchedPolicies = []string{}
			evt.ArgsNum = int(argnum)
			evt.ReturnValue = int(eCtx.Retval)
			evt.Args = args
			evt.StackAddresses = stackAddresses
			evt.ContextFlags = flags
			evt.Syscall = syscall
			evt.Metadata = nil
			// compute hashes using normalized times
			evt.ThreadEntityId = process.HashTaskID(eCtx.HostTid, uint64(evt.ThreadStartTime))
			if eCtx.HostTid == eCtx.HostPid && eCtx.StartTime == eCtx.LeaderStartTime {
				// If the thread is the leader (i.e., HostTid == HostPid and StartTime == LeaderStartTime),
				// then ProcessEntityId and ThreadEntityId are identical and can be shared.
				evt.ProcessEntityId = evt.ThreadEntityId
			} else {
				evt.ProcessEntityId = process.HashTaskID(eCtx.HostPid, timeutil.BootToEpochNS(eCtx.LeaderStartTime))
			}
			evt.ParentEntityId = process.HashTaskID(eCtx.HostPpid, timeutil.BootToEpochNS(eCtx.ParentStartTime))

			// Set internal bitmap from kernel-matched policies
			evt.MatchedPoliciesBitmap = eCtx.MatchedPolicies

			// If there aren't any policies that need filtering in userland, tracee **may** skip
			// this event, as long as there aren't any derivatives or signatures that depend on it.
			// Some base events (derivative and signatures) might not have set related policy bit,
			// thus the need to continue with those within the pipeline.
			if t.matchPolicies(evt) == 0 {
				_, hasDerivation := t.eventDerivations[eventId]
				reqBySig := t.policyManager.IsRequiredBySignature(eventId)

				if !hasDerivation && !reqBySig {
					_ = t.stats.EventsFiltered.Increment()
					t.eventsPool.Put(evt)
					decoderPool.Put(ebpfMsgDecoder)
					continue
				}
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

// matchPolicies does the userland filtering (policy matching) for events. It iterates through all
// existing policies, that were set by the kernel in the event bitmap. Some of those policies might
// not match the event after userland filters are applied. In those cases, the policy bit is cleared
// (so the event is "filtered" for that policy). This may be called in different stages of the
// pipeline (decode, derive, engine).
func (t *Tracee) matchPolicies(event *events.PipelineEvent) uint64 {
	if event == nil || event.Event == nil {
		return 0
	}

	eventID := event.EventID
	bitmap := event.MatchedPoliciesBitmap

	// Short circuit if there are no policies in userland that need filtering.
	if !t.policyManager.FilterableInUserland() {
		event.MatchedPoliciesUser = bitmap // store untouched bitmap to be used in sink stage
		return bitmap
	}

	// Cache frequently accessed event fields
	eventUID := uint32(event.UserID)
	eventPID := uint32(event.HostProcessID)
	eventRetVal := int64(event.ReturnValue)

	// range through each userland filterable policy
	for it := t.policyManager.CreateUserlandIterator(); it.HasNext(); {
		p := it.Next()
		// Policy ID is the bit offset in the bitmap.
		bitOffset := uint(p.ID)

		if !bitwise.HasBit(bitmap, bitOffset) { // event does not match this policy
			continue
		}

		// The event might have this policy bit set, but the policy might not have this
		// event ID. This happens whenever the event submitted by the kernel is going to
		// derive an event that this policy is interested in. In this case, don't do
		// anything and let the derivation stage handle this event.
		rule, ok := p.Rules[eventID]
		if !ok {
			continue
		}

		//
		// Do the userland filtering - ordered by efficiency (cheapest first)
		//

		// 1. UID/PID range checks (very fast)
		if p.UIDFilter.Enabled() {
			if !p.UIDFilter.InMinMaxRange(eventUID) {
				bitwise.ClearBit(&bitmap, bitOffset)
				continue
			}
		}

		if p.PIDFilter.Enabled() {
			if !p.PIDFilter.InMinMaxRange(eventPID) {
				bitwise.ClearBit(&bitmap, bitOffset)
				continue
			}
		}

		// 2. event return value filters (fast)
		if !rule.RetFilter.Filter(eventRetVal) {
			bitwise.ClearBit(&bitmap, bitOffset)
			continue
		}

		// 3. event scope filters (medium cost)
		if !rule.ScopeFilter.Filter(*event.Event) {
			bitwise.ClearBit(&bitmap, bitOffset)
			continue
		}

		// 4. event data filters (potentially expensive)
		// TODO: remove PrintMemDump check once events params are introduced
		//       i.e. print_mem_dump.params.symbol_name=system:security_file_open
		// events.PrintMemDump bypass was added due to issue #2546
		// because it uses usermode applied filters as parameters for the event,
		// which occurs after filtering
		if eventID != events.PrintMemDump && !rule.DataFilter.Filter(event.Args) {
			bitwise.ClearBit(&bitmap, bitOffset)
			continue
		}

		// Early exit optimization: if bitmap becomes 0, no need to continue
		if bitmap == 0 {
			break
		}
	}

	event.MatchedPoliciesUser = bitmap   // store filtered bitmap to be used in sink stage
	event.MatchedPoliciesBitmap = bitmap // update internal bitmap

	return bitmap
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
// that event type.  It also clears policy bits for out-of-order container related events
// (after the processing logic). This stage also starts some logic that will be used by
// the processing logic in subsequent events.
func (t *Tracee) processEvents(ctx context.Context, in <-chan *events.PipelineEvent) (
	<-chan *events.PipelineEvent, <-chan error,
) {
	out := make(chan *events.PipelineEvent, t.config.PipelineChannelSize)
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

			// Get a bitmap with all policies containing container filters
			policiesWithContainerFilter := t.policyManager.WithContainerFilterEnabled()

			// Filter out events that don't have a container ID from all the policies that
			// have container filters. This will guarantee that any of those policies
			// won't get matched by this event. This situation might happen if the events
			// from a recently created container appear BEFORE the initial cgroup_mkdir of
			// that container root directory.  This could be solved by sorting the events
			// by a monotonic timestamp, for example, but sorting might not always be
			// enabled, so, in those cases, ignore the event IF the event is not a
			// cgroup_mkdir or cgroup_rmdir.

			if policiesWithContainerFilter > 0 && event.Container.ID == "" {
				eventId := event.EventID

				// never skip cgroup_{mkdir,rmdir}: container_{create,remove} events need it
				if eventId == events.CgroupMkdir || eventId == events.CgroupRmdir {
					goto sendEvent
				}

				logger.Debugw("False container positive", "event.Timestamp", event.Timestamp,
					"eventId", eventId)

				// remove event from the policies with container filters
				bitwise.ClearBits(&event.MatchedPoliciesKernel, policiesWithContainerFilter)
				bitwise.ClearBits(&event.MatchedPoliciesUser, policiesWithContainerFilter)
				bitwise.ClearBits(&event.MatchedPoliciesBitmap, policiesWithContainerFilter)

				if event.MatchedPoliciesKernel == 0 {
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
func (t *Tracee) deriveEvents(ctx context.Context, in <-chan *events.PipelineEvent) (
	<-chan *events.PipelineEvent, <-chan error,
) {
	out := make(chan *events.PipelineEvent, t.config.PipelineChannelSize)
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
				// Extract trace.Event for derivation
				derivatives, errors := t.eventDerivations.DeriveEvent(event.Event)

				// Send original event down the pipeline
				out <- event

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
					derivativeEvent := &derivatives[i]

					// Wrap derived event in PipelineEvent
					derivativePipelineEvent := events.NewPipelineEvent(derivativeEvent)

					// Skip events that dont work with filtering due to missing types
					// being handled (https://github.com/aquasecurity/tracee/issues/2486)
					switch events.ID(derivatives[i].EventID) {
					case events.SymbolsLoaded:
					case events.SharedObjectLoaded:
					case events.PrintMemDump:
					default:
						// Derived events might need filtering as well
						if t.matchPolicies(derivativePipelineEvent) == 0 {
							_ = t.stats.EventsFiltered.Increment()
							continue
						}
					}

					// Process derived events
					t.processEvent(derivativePipelineEvent)
					out <- derivativePipelineEvent
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	return out, errc
}

// detectEvents is the detector dispatch pipeline stage. For each received event, it dispatches
// the event to registered detectors that are interested in it. Detectors can produce new events
// (derived or threat events) that flow through the pipeline. Supports detector chains with
// breadth-first processing up to a maximum depth to prevent infinite loops.
func (t *Tracee) detectEvents(ctx context.Context, in <-chan *events.PipelineEvent) (
	<-chan *events.PipelineEvent, <-chan error,
) {
	out := make(chan *events.PipelineEvent, t.config.PipelineChannelSize)
	errc := make(chan error, 1)

	// Maximum depth for detector chains (prevents infinite loops)
	// Expected: raw event → derived event → threat event → threat event (depth 4)
	const maxDetectorChainDepth = 5

	go func() {
		defer close(out)
		defer close(errc)

		for {
			select {
			case event := <-in:
				if event == nil {
					continue
				}

				// Send original event down the pipeline first
				out <- event

				// Convert to v1beta1.Event for detector API (uses cached conversion)
				pbEvent := event.ToProto()

				// Process event through detector chain using breadth-first traversal
				queue := []*pb.Event{pbEvent}

				for depth := 0; depth < maxDetectorChainDepth && len(queue) > 0; depth++ {
					var nextDepth []*pb.Event

					// Process all events at current depth
					for _, evt := range queue {
						// Dispatch to detectors
						outputs, err := t.detectorEngine.DispatchToDetectors(ctx, evt)
						if err != nil {
							t.handleError(err)
							continue
						}

						// Filter and route outputs
						for _, output := range outputs {
							// Convert v1beta1.Event back to trace.Event
							traceEvent := events.ConvertFromProto(output)

							// Wrap in PipelineEvent and inherit policy bitmap from input event
							pipelineEvent := events.NewPipelineEvent(traceEvent)
							pipelineEvent.MatchedPoliciesBitmap = event.MatchedPoliciesBitmap

							// Apply policy filtering to detector outputs
							if t.matchPolicies(pipelineEvent) == 0 {
								continue // Skip events not matching policy
							}

							// Send to output
							out <- pipelineEvent

							// Queue for next depth - any detector output might be consumed by other detectors
							nextDepth = append(nextDepth, output)
						}
					}

					queue = nextDepth
				}

				// Safety check - log if max depth exceeded
				if len(queue) > 0 {
					_ = t.stats.ErrorCount.Increment()
					logger.Errorw("Exceeded max detector chain depth",
						"max_depth", maxDetectorChainDepth,
						"remaining_events", len(queue))
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
func (t *Tracee) sinkEvents(ctx context.Context, in <-chan *events.PipelineEvent) <-chan error {
	errc := make(chan error, 1)

	go func() {
		defer close(errc)

		for event := range in {
			if event == nil || event.Event == nil {
				continue // might happen during initialization (ctrl+c seg faults)
			}

			// Convert to protobuf once at the beginning of sink stage
			// ToProto() returns nil if event data is nil/invalid
			pbEvent := event.ToProto()
			if pbEvent == nil {
				t.eventsPool.Put(event)
				continue
			}

			// Is the event enabled for the policies or globally?
			if !t.policyManager.IsEnabled(event.MatchedPoliciesBitmap, event.EventID) {
				// TODO: create metrics from dropped events
				t.eventsPool.Put(event)
				continue
			}

			// Only emit events requested by the user and matched by at least one policy.
			event.MatchedPoliciesBitmap = t.policyManager.MatchEvent(event.EventID, event.MatchedPoliciesBitmap)
			if event.MatchedPoliciesBitmap == 0 {
				t.eventsPool.Put(event)
				continue
			}

			// Populate the protobuf event with the names of the matched policies.
			if pbEvent.Policies == nil {
				pbEvent.Policies = &pb.Policies{}
			}
			pbEvent.Policies.Matched = t.policyManager.MatchedNames(event.MatchedPoliciesBitmap)

			// Parse arguments for output formatting if enabled.
			if t.config.Output.ParseArguments {
				err := events.ParseDataFields(pbEvent.Data, int(pbEvent.Id))
				if err != nil {
					t.handleError(err)
				}
			}

			if t.config.Output.ParseArgumentsFDs {
				// Use original timestamp from pipeline metadata for BPF map lookup
				err := events.ParseDataFieldsFDs(pbEvent.Data, event.Timestamp, t.FDArgPathMap)
				if err != nil {
					t.handleError(err)
				}
			}

			// Send the event to the streams.
			select {
			case <-ctx.Done():
				return
			default:
				if t.streamsManager.HasSubscribers() {
					// Translate event ID to external format for streams (external API boundary)
					pbEvent.Id = pb.EventId(events.TranslateEventID(int(pbEvent.Id)))
					t.streamsManager.Publish(ctx, pbEvent, event.MatchedPoliciesBitmap)
				}
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

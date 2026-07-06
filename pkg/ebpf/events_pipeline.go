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
	"github.com/aquasecurity/tracee/common/intern"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/common/stringutil"
	"github.com/aquasecurity/tracee/common/timeutil"
	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/pkg/datastores/process"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/policy"
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
func (t *Tracee) handleEvents(ctx context.Context, initialized chan<- struct{}, done chan<- struct{}) {
	logger.Debugw("Starting handleEvents goroutine")
	defer logger.Debugw("Stopped handleEvents goroutine")
	defer close(done) // Signal that pipeline has fully drained

	var errcList []<-chan error

	// Decode stage: events are read from the perf buffer and decoded into trace.Event type.

	eventsChan, errc := t.decodeEvents(t.eventsChannel)
	t.stats.Channels["decode"] = eventsChan
	errcList = append(errcList, errc)

	// Sort stage: events go through a sorting function.

	if t.config.Output.EventsSorting {
		eventsChan, errc = t.eventsSorter.StartPipeline(eventsChan, t.config.Buffers.Kernel.Artifacts)
		t.stats.Channels["sort"] = eventsChan
		errcList = append(errcList, errc)
	}

	// Process events stage: ctx needed for FtraceHook background goroutine.

	eventsChan, errc = t.processEvents(ctx, eventsChan)
	t.stats.Channels["process"] = eventsChan
	errcList = append(errcList, errc)

	// Enrichment stage: container events are enriched with additional runtime data.

	if t.config.EnrichmentEnabled {
		eventsChan, errc = t.enrichContainerEvents(eventsChan)
		t.stats.Channels["enrich"] = eventsChan
		errcList = append(errcList, errc)
	}

	// Derive events stage: events go through a derivation function.

	eventsChan, errc = t.deriveEvents(eventsChan)
	t.stats.Channels["derive"] = eventsChan
	errcList = append(errcList, errc)

	// Detect events stage: ctx passed through to detector OnEvent interface.
	// Only wire the stage when detectors are actually registered. With none
	// (e.g. signature-based deployments), skipping the stage avoids a goroutine,
	// a pipeline-sized channel, the per-event hand-off, and the early proto
	// conversion it forces - the sink performs that conversion anyway.

	if t.detectorEngine != nil && t.detectorEngine.GetDetectorCount() > 0 {
		eventsChan, errc = t.detectEvents(ctx, eventsChan)
		t.stats.Channels["detect"] = eventsChan
		errcList = append(errcList, errc)
	}

	// Engine events stage: events go through the signatures engine for detection.

	if t.config.EngineConfig.Mode == engine.ModeSingleBinary {
		eventsChan, errc = t.engineEvents(eventsChan)
		t.stats.Channels["engine"] = eventsChan
		errcList = append(errcList, errc)
	}

	// Sink pipeline stage: events go through printers.

	errc = t.sinkEvents(eventsChan)
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
func (t *Tracee) decodeEvents(sourceChan chan []byte) (<-chan *events.PipelineEvent, <-chan error) {
	out := make(chan *events.PipelineEvent, t.config.Buffers.Pipeline)
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
			if t.config.Output.UserStack {
				stackAddresses = t.getStackAddresses(eCtx.StackID)
			}

			_, containerInfo := t.dataStoreRegistry.GetContainerManager().GetCgroupInfo(eCtx.CgroupID)

			// Intern frequently repeated strings to reduce RSS memory usage.
			// ProcessName (comm) and HostName (utsname) are created from byte buffers
			// on every event, but typically have a small set of unique values. Interning
			// ensures identical strings share the same backing array.
			commStr := intern.String(string(stringutil.TrimTrailingNUL(eCtx.Comm[:])))
			utsNameStr := intern.String(string(stringutil.TrimTrailingNUL(eCtx.UtsName[:])))

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
			// Intern container and Kubernetes metadata strings. These repeat for
			// every event from the same cgroup/pod but are re-assigned per event.
			containerId := intern.String(containerInfo.ContainerId)
			evt.ContainerID = containerId
			evt.Container = trace.Container{
				ID:          containerId,
				ImageName:   intern.String(containerInfo.Image),
				ImageDigest: intern.String(containerInfo.ImageDigest),
				Name:        intern.String(containerInfo.Name),
			}
			evt.Kubernetes = trace.Kubernetes{
				PodName:      intern.String(containerInfo.Pod.Name),
				PodNamespace: intern.String(containerInfo.Pod.Namespace),
				PodUID:       intern.String(containerInfo.Pod.UID),
			}
			evt.EventName = evtName
			evt.RulesVersion = eCtx.PoliciesVersion
			evt.MatchedRulesKernel = []uint64{eCtx.MatchedPolicies}
			evt.MatchedRulesUser = nil
			evt.MatchedPolicies = []string{}
			evt.ArgsNum = int(argnum)

			// Extract return value from Args if present (stored as the last argument)
			evt.ReturnValue = extractReturnValue(args, evt.EventName)

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

			// Set the internal working bitmap from the kernel-matched rules.
			// The kernel emits a single u64 of rule bits (IDs 0-63); rule IDs >= 64
			// are evaluated in userland by matchOverflowRules below.
			// Net base events (IDs < MaxNetID) carry a socket-derived kernel bitmap keyed by the
			// socket-creation event's rule ids, not this event's, so it is unreliable in the
			// per-event rule-id model and is only a coarse submit gate. Recompute in userland:
			// start with every rule as a candidate and let matchOverflowRules + matchPolicies narrow
			// by scope from the event's own workload; deriveEvents then remaps to the derived net
			// events. See docs/matched-rules-net-matched-rules-fix.md.
			if eventId >= events.NetPacketBase && eventId < events.MaxNetID {
				evt.MatchedRulesBitmap = t.policyManager.GetAllRulesBitmap(eventId)
			} else {
				evt.MatchedRulesBitmap = []uint64{eCtx.MatchedPolicies}
			}

			// Evaluate scope filters for overflow rules (ID >= 64) that the kernel's
			// single-u64 bitmap can't represent. Kernel-origin events only (this is the
			// decode stage); derived/finding events keep their mapped bitmap.
			t.matchOverflowRules(evt)

			// Apply userland rule filtering. A base event needed to derive an event a policy wants
			// carries a scope-filtered DEPENDENCY rule: every derived event declares its derive-from as
			// a dependency (pkg/events/core.go), and every derivation is gated on the derived event being
			// selected (initDerivationTable Enabled = IsEventSelected), so matchPolicies already keeps
			// exactly those bases - and only when the workload scope matches. If nothing (user or
			// dependency rule) matched, the event feeds nothing wanted, so drop it here. (The old coarse
			// per-event-type eventDerivations keep - and before it requiredBySignature - are both gone.)
			if !t.matchPolicies(evt) {
				_ = t.stats.EventsFiltered.Increment()
				t.eventsPool.Put(evt)
				decoderPool.Put(ebpfMsgDecoder)
				continue
			}

			out <- evt

			// Return decoder to pool for reuse
			decoderPool.Put(ebpfMsgDecoder)
		}
	}()
	return out, errc
}

// matchPolicies does the userland filtering (rule matching) for events. The kernel
// sets a bitmap of matched rule IDs; here each userland-filterable rule for this
// event is re-checked, and its bit is cleared when a userland filter rejects the
// event. Rules whose policy/event has no userland filters are left untouched (their
// kernel match stands). Returns true if any rule still matches. May be called in
// different stages of the pipeline (decode, derive, engine).
//
// clearDisabledRules removes, in place, the bits of rules disabled at runtime (DisableRule)
// from the event's working bitmap. No-op (and no allocation) when nothing is disabled.
func (t *Tracee) clearDisabledRules(eventID events.ID, bitmap []uint64) {
	if !t.policyManager.AnyRulesDisabled() { // lock-free fast path: nothing ever disabled
		return
	}
	disabled := t.policyManager.GetDisabledRules(eventID)
	for i := 0; i < len(bitmap) && i < len(disabled); i++ {
		bitmap[i] &^= disabled[i]
	}
}

func (t *Tracee) matchPolicies(event *events.PipelineEvent) bool {
	if event == nil || event.Event == nil {
		return false
	}

	eventID := event.EventID

	// NOTE: rules with ID >= 64 (overflow) are evaluated by the caller via matchOverflowRules,
	// for KERNEL-origin events only (the kernel's single-u64 bitmap can't represent them).
	// Derived and finding events arrive with their bitmap already mapped from the base event,
	// so their overflow bits must NOT be recomputed here - the loop below only narrows them.
	bitmap := event.MatchedRulesBitmap // working copy (copied from the kernel bitmap in NewPipelineEvent)

	// Drop rules disabled at runtime (DisableRule).
	t.clearDisabledRules(eventID, bitmap)

	// Cache frequently accessed event fields
	eventUID := uint32(event.UserID)
	eventPID := uint32(event.HostProcessID)
	eventRetVal := int64(event.ReturnValue)

	// range through each userland-filterable rule for this event
	for _, rule := range t.policyManager.GetUserlandRules(eventID) {
		// Rule bit may live beyond word 0, so use the array-aware accessor.
		if !bitwise.HasBitInArray(bitmap, rule.ID) { // event does not match this rule
			continue
		}

		//
		// Do the userland filtering - ordered by efficiency (cheapest first)
		//

		// 1. UID/PID range checks (very fast)
		if rule.Policy.UIDFilter.Enabled() {
			if !rule.Policy.UIDFilter.InMinMaxRange(eventUID) {
				bitwise.ClearBitInArray(&bitmap, rule.ID)
				continue
			}
		}

		if rule.Policy.PIDFilter.Enabled() {
			if !rule.Policy.PIDFilter.InMinMaxRange(eventPID) {
				bitwise.ClearBitInArray(&bitmap, rule.ID)
				continue
			}
		}

		// 2. event scope filters (medium cost). Scope filters are workload-level
		// (uid/pid/comm/container/tree/...) and valid on every event in a dependency
		// chain, so they apply to dependency rules too.
		if !rule.Data.ScopeFilter.Filter(*event.Event) {
			bitwise.ClearBitInArray(&bitmap, rule.ID)
			continue
		}

		// Phase 2: an optional detector-declared scope filter pushed onto this (base) dependency
		// rule from the detector's Requirements.Events[]. It is workload-level like the policy scope
		// above and is ANDed with it (nil for ordinary rules).
		if rule.DetectorScopeFilter != nil && !rule.DetectorScopeFilter.Filter(*event.Event) {
			bitwise.ClearBitInArray(&bitmap, rule.ID)
			continue
		}

		// Dependency rules are scope-only (see EventRule.IsDependency): their shared
		// RuleData's return-value and data filters belong to the dependent/derived
		// event's schema, not this base event. Applying them here would wrongly drop
		// base events (e.g. a data.pathname filter on a derived event has no pathname
		// field on its base) and break derivations; the ret/data filters are applied
		// when the derived event itself is matched.
		if rule.IsDependency() {
			continue
		}

		// 3. event return value filters (fast)
		if !rule.Data.RetFilter.Filter(eventRetVal) {
			bitwise.ClearBitInArray(&bitmap, rule.ID)
			continue
		}

		// 4. event data filters (potentially expensive)
		// TODO: remove PrintMemDump check once events params are introduced
		//       i.e. print_mem_dump.params.symbol_name=system:security_file_open
		// events.PrintMemDump bypass was added due to issue #2546
		// because it uses usermode applied filters as parameters for the event,
		// which occurs after filtering
		if eventID != events.PrintMemDump && !rule.Data.DataFilter.Filter(event.Args) {
			bitwise.ClearBitInArray(&bitmap, rule.ID)
			continue
		}

		// Phase 2: a detector's per-base-event data filter (rule-local) applies to THIS base event's
		// args, unlike Data.DataFilter which belongs to the dependent/derived event. AND it in.
		if eventID != events.PrintMemDump && rule.DetectorDataFilter != nil &&
			!rule.DetectorDataFilter.Filter(event.Args) {
			bitwise.ClearBitInArray(&bitmap, rule.ID)
			continue
		}

		// Early exit optimization: if the bitmap becomes empty, no need to continue
		if bitwise.IsBitmapArrayEmpty(bitmap) {
			break
		}
	}

	event.MatchedRulesBitmap = bitmap // update internal working bitmap
	event.MatchedRulesUser = bitmap   // store filtered bitmap to be used in sink stage

	return !bitwise.IsBitmapArrayEmpty(bitmap)
}

// matchOverflowRules evaluates, in userland, the kernel-side scope filters for rules with
// ID >= 64. The kernel's matched_rules is a single u64 and cannot represent them, so the BPF
// code leaves them out entirely. This mirrors the eBPF match_scope_filters logic
// (res &= equality_filter_matches(...) | mask, per overflow word) using the retained Go
// filter maps, and writes the resulting overflow words into event.MatchedRulesBitmap. The
// userland pass in matchPolicies then applies the per-rule ret/data/rich-scope filters to
// those bits. Tree/follow/binary overflow rules are not handled here (tree/follow are 0-63
// only by design); pid filtering checks host pid only (not tid), matching the prior model.
func (t *Tracee) matchOverflowRules(event *events.PipelineEvent) {
	eventID := event.EventID
	if !t.policyManager.HasOverflowRules(eventID) {
		return
	}

	// One 64-bit word per 64 rules. The kernel filled word 0 (rules 0-63); size the bitmap to
	// cover ALL rules by COUNT (not by which scope filters happen to be set) and init each
	// overflow word (index 1+) to its VALID candidate rules (mirrors the kernel initializing
	// matched_rules to the event's candidate rules; no phantom bits beyond the real rule
	// count). This alone makes overflow rules with NO scope filter match unconditionally; the
	// scope filters below only narrow. Word 0 is owned by the kernel and left untouched.
	rulesCount := t.policyManager.GetRulesCount(eventID)
	neededWords := int((rulesCount + 63) / 64)
	bitmap := event.MatchedRulesBitmap
	for len(bitmap) < neededWords {
		bitmap = append(bitmap, 0)
	}
	for i := 1; i < neededWords; i++ {
		bitmap[i] = validRulesMask(rulesCount, i)
	}
	event.MatchedRulesBitmap = bitmap // store the grown slice (scope filters below mutate it in place)

	// Apply the kernel-side scope filters for the overflow rules, if any are configured for
	// this event. No filter map / no config => no scope filters => the candidate bits stand.
	fMaps := t.policyManager.GetFilterMaps()
	if fMaps == nil {
		return
	}
	cfg, ok := fMaps.ExtendedScopeFilterConfigs[eventID]
	if !ok {
		return
	}

	vKey := policy.FilterVersionKey{Version: event.RulesVersion, EventID: uint32(eventID)}

	// Apply each scope filter to the overflow words. A nil/absent inner map (key not present,
	// including an empty container id) yields the key-missing behavior naturally.
	applyOverflowScopeFilter(bitmap, strBitmaps(fMaps.CommFilters[vKey], event.ProcessName), cfg.CommFilterEnabled, cfg.CommFilterMatchIfKeyMissing)
	applyOverflowScopeFilter(bitmap, u64Bitmaps(fMaps.UIDFilters[vKey], uint64(event.UserID)), cfg.UIDFilterEnabled, cfg.UIDFilterMatchIfKeyMissing)
	applyOverflowScopeFilter(bitmap, u64Bitmaps(fMaps.PIDFilters[vKey], uint64(event.HostProcessID)), cfg.PIDFilterEnabled, cfg.PIDFilterMatchIfKeyMissing)
	applyOverflowScopeFilter(bitmap, u64Bitmaps(fMaps.MntNsFilters[vKey], uint64(event.MountNS)), cfg.MntNsFilterEnabled, cfg.MntNsFilterMatchIfKeyMissing)
	applyOverflowScopeFilter(bitmap, u64Bitmaps(fMaps.PidNsFilters[vKey], uint64(event.PIDNS)), cfg.PidNsFilterEnabled, cfg.PidNsFilterMatchIfKeyMissing)
	applyOverflowScopeFilter(bitmap, strBitmaps(fMaps.UTSFilters[vKey], event.HostName), cfg.UtsNsFilterEnabled, cfg.UtsNsFilterMatchIfKeyMissing)
	// cgroup is keyed by the 32-bit LSB on both sides (see kernel cgroup_id_lsb and
	// FindContainerCgroupID32LSB), so truncate to u32 before the lookup.
	applyOverflowScopeFilter(bitmap, u64Bitmaps(fMaps.CgroupFilters[vKey], uint64(uint32(event.CgroupID))), cfg.CgroupIdFilterEnabled, cfg.CgroupIdFilterMatchIfKeyMissing)
	applyOverflowScopeFilter(bitmap, strBitmaps(fMaps.ContainerFilters[vKey], event.ContainerID), cfg.ContFilterEnabled, cfg.ContFilterMatchIfKeyMissing)
	// NOTE: binary/executable scope is intentionally NOT narrowed here. matchOverflowRules runs in the decode
	// stage, before the proctree processor populates event.Executable.Path (see processor_proctree.go), so the
	// binary path is not yet available. An overflow rule (ID >= 64) scoped by executable therefore keeps its
	// (unevaluated) bit here and is narrowed later by narrowOverflowBinaryScope, in the processEvents stage,
	// once the path is set and before deriveEvents reads the matched set. That pass SKIPS narrowing when the
	// path is unresolvable (e.g. exiting processes) - over-attributing rather than dropping - so enforcement is
	// exact for live-process events (exec, security_file_open, ...) and degrades safely otherwise. Do NOT
	// narrow binary HERE with the absent path: it would force a verdict on empty data and drop legitimate
	// events. Tree/follow are 0-63 only, so they never overflow. Full exit-event enforcement would need the
	// binary from the kernel event context or the staged model (docs/deferred-filter-evaluation.md).
	// (scope filters mutate bitmap in place; it was already stored on the event above)
}

// validRulesMask returns the bitmap of valid rule positions within overflow word `word`,
// given the event's total rule count (bits for positions beyond the real rules stay 0).
func validRulesMask(rulesCount uint, word int) uint64 {
	low := uint(word) * 64
	if rulesCount <= low {
		return 0
	}
	if n := rulesCount - low; n < 64 {
		return (uint64(1) << n) - 1
	}
	return ^uint64(0)
}

// applyOverflowScopeFilter applies one scope filter to the overflow words (index 1+),
// mirroring eBPF: res &= (equals_in_rules | (match_if_key_missing & ~key_used_in_rules)) | mask
// where mask = ~filter_enabled (rules without this filter are unaffected). bitmaps holds the
// per-word {equals,key_used} for the looked-up key (nil => key missing).
func applyOverflowScopeFilter(bitmap []uint64, bitmaps []policy.RuleBitmap, filterEnabled, matchIfKeyMissing []uint64) {
	for i := 1; i < len(bitmap); i++ {
		mask := ^uint64(0) // rules without this filter enabled are unaffected
		if i < len(filterEnabled) {
			mask = ^filterEnabled[i]
		}
		var matchIfMissing uint64
		if i < len(matchIfKeyMissing) {
			matchIfMissing = matchIfKeyMissing[i]
		}
		var equals, keyUsed uint64
		if i < len(bitmaps) {
			equals = bitmaps[i].EqualsInRules
			keyUsed = bitmaps[i].KeyUsedInRules
		}
		filterMatches := equals | (matchIfMissing & ^keyUsed)
		bitmap[i] &= filterMatches | mask
	}
}

// u64Bitmaps / strBitmaps look up the per-word rule bitmaps for a key in a filter inner map,
// returning nil when the map or key is absent (key-missing behavior).
func u64Bitmaps(m map[uint64][]policy.RuleBitmap, key uint64) []policy.RuleBitmap {
	if m == nil {
		return nil
	}
	return m[key]
}

func strBitmaps(m map[string][]policy.RuleBitmap, key string) []policy.RuleBitmap {
	if m == nil {
		return nil
	}
	return m[key]
}

// binaryBitmaps looks up the per-word rule bitmaps for an event's binary, mirroring the kernel's
// binary_filter_matches double lookup: the path-only key (any mount namespace, stored as {MntNS: 0, Path})
// is tried first, then the namespace-specific {MntNS, Path}. Returns nil when the map or key is absent.
func binaryBitmaps(m map[filters.NSBinary][]policy.RuleBitmap, path string, mntNS uint32) []policy.RuleBitmap {
	if m == nil {
		return nil
	}
	if bm, ok := m[filters.NSBinary{MntNS: 0, Path: path}]; ok {
		return bm
	}
	return m[filters.NSBinary{MntNS: mntNS, Path: path}]
}

// narrowOverflowBinaryScope enforces executable/binary scope for OVERFLOW rules (ID >= 64) that
// matchOverflowRules deliberately left un-narrowed at decode, because the binary path is only populated
// later by the proctree processor. It runs in the processEvents stage AFTER that processor and BEFORE
// deriveEvents (which reads MatchedRulesUser), so the matched set is final before anything consumes it.
// It only ever clears overflow bits; an event narrowed to no matching rule is dropped at the sink terminal
// drop, so no new drop point is needed. Rules 0-63 are enforced in the kernel and are untouched here.
//
// SAFETY: if the binary is unresolvable (event.Executable.Path == ""), we SKIP narrowing rather than treat
// the empty path as a key-miss. An equal executable filter on a missing key would clear the bit and DROP a
// legitimate event. This happens for post-mortem events like sched_process_exit, where the process is already
// gone from the process tree so procTreeAddBinInfo cannot fill the path. Skipping leaves the overflow bit set
// -> over-attribution (the pre-existing binary/tree limitation), which is correct-but-imprecise, never a drop.
// Live-process events (sched_process_exec, security_file_open, ...) do carry the path and are enforced exactly.
func (t *Tracee) narrowOverflowBinaryScope(event *events.PipelineEvent) {
	eventID := event.EventID
	if !t.policyManager.HasOverflowRules(eventID) {
		return
	}
	if event.Executable.Path == "" {
		return // binary unresolvable (e.g. exiting process): over-attribute rather than drop
	}
	fMaps := t.policyManager.GetFilterMaps()
	if fMaps == nil {
		return
	}
	cfg, ok := fMaps.ExtendedScopeFilterConfigs[eventID]
	if !ok {
		return
	}

	vKey := policy.FilterVersionKey{Version: event.RulesVersion, EventID: uint32(eventID)}
	binBitmaps := binaryBitmaps(fMaps.BinaryFilters[vKey], event.Executable.Path, uint32(event.MountNS))

	// MatchedRulesBitmap and MatchedRulesUser alias the same slice after decode, but narrow both defensively
	// (the operation only clears bits and is idempotent). MatchedRulesKernel holds word 0 only, which the
	// overflow narrowing (words 1+) never touches.
	applyOverflowScopeFilter(event.MatchedRulesBitmap, binBitmaps, cfg.BinPathFilterEnabled, cfg.BinPathFilterMatchIfKeyMissing)
	applyOverflowScopeFilter(event.MatchedRulesUser, binBitmaps, cfg.BinPathFilterEnabled, cfg.BinPathFilterMatchIfKeyMissing)
}

// matchPoliciesProto does userland filtering for proto-native events (detector outputs).
// It extracts fields from pb.Event and applies the same filtering logic as matchPolicies.
// Note: This function applies only basic filters (UID/PID) and skips RetFilter, ScopeFilter,
// and DataFilter since they require trace.Event. This is acceptable since detector outputs
// typically don't need complex filtering.
func (t *Tracee) matchPoliciesProto(pipelineEvent *events.PipelineEvent) bool {
	if pipelineEvent == nil || pipelineEvent.ProtoEvent == nil {
		return false
	}

	pbEvent := pipelineEvent.ProtoEvent

	eventID := pipelineEvent.EventID
	bitmap := pipelineEvent.MatchedRulesBitmap // working copy of the matched-rules bitmap

	// Drop rules disabled at runtime (DisableRule).
	t.clearDisabledRules(eventID, bitmap)

	// Extract fields from protobuf for filtering using helper functions
	eventUID := pb.GetProcessRealUserId(pbEvent)
	eventPID := pb.GetProcessHostPid(pbEvent)

	// range through each userland-filterable rule for this event
	for _, rule := range t.policyManager.GetUserlandRules(eventID) {
		if !bitwise.HasBitInArray(bitmap, rule.ID) { // event does not match this rule
			continue
		}

		// Apply fast filters (UID/PID only for proto-native events)
		if rule.Policy.UIDFilter.Enabled() {
			if !rule.Policy.UIDFilter.InMinMaxRange(eventUID) {
				bitwise.ClearBitInArray(&bitmap, rule.ID)
				continue
			}
		}

		if rule.Policy.PIDFilter.Enabled() {
			if !rule.Policy.PIDFilter.InMinMaxRange(eventPID) {
				bitwise.ClearBitInArray(&bitmap, rule.ID)
				continue
			}
		}

		// RetFilter, ScopeFilter, and DataFilter are skipped for proto-native events
		// since they require trace.Event fields that aren't available.
		// This is acceptable since detector outputs typically don't need complex filtering.
		//
		// TODO: Once the entire pipeline is migrated to use proto events, we should
		// re-implement these filters to work directly with protobuf fields and restore
		// full filtering capabilities for all events.

		// Early exit optimization: if the bitmap becomes empty, no need to continue
		if bitwise.IsBitmapArrayEmpty(bitmap) {
			break
		}
	}

	pipelineEvent.MatchedRulesBitmap = bitmap // update internal bitmap

	return !bitwise.IsBitmapArrayEmpty(bitmap)
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
	out := make(chan *events.PipelineEvent, t.config.Buffers.Pipeline)
	errc := make(chan error, 1)

	// Some "informational" events are started here (TODO: API server?)
	// initEventsWg tracks background goroutines (e.g. FtraceHookEvent) that send
	// to out. We must wait for them to finish before closing out.
	var initEventsWg sync.WaitGroup
	t.invokeInitEvents(ctx, out, &initEventsWg)

	go func() {
		// Defers run LIFO: initWg.Wait() first, then close(errc), then close(out).
		// This ensures init goroutines finish before the output channel is closed.
		defer close(out)
		defer close(errc)
		defer initEventsWg.Wait()

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

			// Get the bitmap of rules (for this event) that have container filters.
			containerFilteredRules := t.policyManager.GetContainerFilteredRulesBitmap(event.EventID)

			// Filter out events that don't have a container ID from all the rules that
			// have container filters. This will guarantee that any of those rules
			// won't get matched by this event. This situation might happen if the events
			// from a recently created container appear BEFORE the initial cgroup_mkdir of
			// that container root directory.  This could be solved by sorting the events
			// by a monotonic timestamp, for example, but sorting might not always be
			// enabled, so, in those cases, ignore the event IF the event is not a
			// cgroup_mkdir or cgroup_rmdir.

			if !bitwise.IsBitmapArrayEmpty(containerFilteredRules) && event.Container.ID == "" {
				eventId := event.EventID

				// never skip cgroup_{mkdir,rmdir}: container_{create,remove} events need it
				if eventId == events.CgroupMkdir || eventId == events.CgroupRmdir {
					goto sendEvent
				}

				logger.Debugw("False container positive", "event.Timestamp", event.Timestamp,
					"eventId", eventId)

				// remove the container-filtered rule bits from the event's bitmaps
				// (across all overflow words, so rule IDs >= 64 are handled too)
				clearContainerBits := func(dst []uint64) {
					for i := 0; i < len(dst) && i < len(containerFilteredRules); i++ {
						bitwise.ClearBits(&dst[i], containerFilteredRules[i])
					}
				}
				clearContainerBits(event.MatchedRulesKernel)
				clearContainerBits(event.MatchedRulesUser)
				clearContainerBits(event.MatchedRulesBitmap)

				if bitwise.IsBitmapArrayEmpty(event.MatchedRulesKernel) {
					t.eventsPool.Put(event)
					continue
				}
			}

		sendEvent:
			// Enforce executable/binary scope for overflow rules now that the proctree processor
			// (above) has populated event.Executable.Path - matchOverflowRules could not at decode.
			t.narrowOverflowBinaryScope(event)

			// NOTE: We do NOT check ctx.Done() here - we continue sending events
			// until the input channel is closed. This ensures graceful drain.
			out <- event
		}
	}()
	return out, errc
}

// deriveEvents is the event derivation pipeline stage. For each received event, it runs
// the event derivation logic, described in the derivation table, and sends the derived
// events down the pipeline.
func (t *Tracee) deriveEvents(in <-chan *events.PipelineEvent) (
	<-chan *events.PipelineEvent, <-chan error,
) {
	out := make(chan *events.PipelineEvent, t.config.Buffers.Pipeline)
	errc := make(chan error, 1)

	go func() {
		defer close(out)
		defer close(errc)

		// NOTE: Use for-range to naturally exit when input channel is closed.
		// This ensures all events are processed during graceful shutdown.
		for event := range in {
			if event == nil {
				continue // might happen during initialization (ctrl+c seg faults)
			}

			// Derive events using original event pointer directly (no copying needed)
			// We derive before sending the event downstream to avoid race conditions
			// Extract trace.Event for derivation
			derivatives, errors := t.eventDerivations.DeriveEvent(event.Event)

			// Capture the base event's identity and matched-rules bitmap BEFORE
			// sending it downstream (downstream stages may recycle the pooled event).
			// The derived events' matched rules are computed from these.
			baseEventID := event.EventID
			baseEventMatchedRules := event.MatchedRulesUser

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

				// Map the base event's matched rules to this derived event's own rule
				// IDs (the kernel/base bitmap is keyed by the base event's rule IDs, not
				// the derived event's). See PolicyManager.GetDerivedEventMatchedRules.
				derivedMatched := t.policyManager.GetDerivedEventMatchedRules(
					events.ID(derivativeEvent.EventID), // derived event ID
					baseEventID,                        // base event ID
					baseEventMatchedRules,              // base event matched-rules bitmap
				)
				derivativeEvent.MatchedRulesKernel = derivedMatched
				derivativeEvent.MatchedRulesUser = derivedMatched

				// Wrap derived event in PipelineEvent
				derivativePipelineEvent := events.NewPipelineEvent(derivativeEvent)

				// Skip events that dont work with filtering due to missing types
				// being handled (https://github.com/aquasecurity/tracee/issues/2486)
				switch events.ID(derivatives[i].EventID) {
				case events.SymbolsLoaded, events.SharedObjectLoaded, events.PrintMemDump:
				default:
					// Derived events might need filtering as well
					if !t.matchPolicies(derivativePipelineEvent) {
						_ = t.stats.EventsFiltered.Increment()
						continue
					}
				}

				// Process derived events
				t.processEvent(derivativePipelineEvent)
				out <- derivativePipelineEvent
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
	out := make(chan *events.PipelineEvent, t.config.Buffers.Pipeline)
	errc := make(chan error, 1)

	// Maximum depth for detector chains (prevents infinite loops)
	// Expected: raw event -> derived event -> threat event -> threat event (depth 4)
	const maxDetectorChainDepth = 5

	go func() {
		defer close(out)
		defer close(errc)

		// NOTE: Use for-range to naturally exit when input channel is closed.
		// All downstream stages (engine, sink) also use for-range with blocking
		// sends, so the output channel is always being consumed. No event that
		// has entered the pipeline will be dropped.
		for event := range in {
			if event == nil {
				continue
			}

			// Capture matched-rules context BEFORE sending event downstream to avoid
			// race conditions (the event may be recycled by downstream stages).
			matchedRulesBitmap := event.MatchedRulesBitmap
			baseEventID := event.EventID

			// Convert to v1beta1.Event for detector API BEFORE sending downstream
			// (uses cached conversion, but we get the pointer before potential race)
			pbEvent := event.ToProto()

			// Dispatch to detectors FIRST (before sending downstream)
			// This prevents race condition where sink stage might modify the cached proto
			// while detectors are still reading from it
			outputs, err := t.detectorEngine.DispatchToDetectors(ctx, pbEvent)

			// Send original event downstream (blocking - sink always consumes)
			out <- event

			// Handle dispatch error
			if err != nil {
				t.handleError(err)
				continue
			}

			if len(outputs) == 0 {
				continue
			}

			// Each detector output is a DERIVED event with its OWN rule IDs, so the base
			// event's matched-rules bitmap can't be inherited verbatim - it is mapped onto the
			// output's rule IDs with GetDerivedEventMatchedRules, then narrowed by the output's
			// own filters (matchPoliciesProto).
			//
			// ALL chain levels map from the ORIGINAL base event (not the immediate parent):
			// addTransitiveDependencyRules attaches a dependency rule for every transitive
			// derived event onto the base, so the base's bitmap resolves any output at any
			// depth. Mapping from the parent would fail - the parent's mapped bitmap carries
			// only the parent's own selected bit, not its deeper dependency bits. baseEventID
			// and matchedRulesBitmap were captured before forwarding (the base may be recycled).
			queue := outputs
			for depth := 0; depth < maxDetectorChainDepth && len(queue) > 0; depth++ {
				var nextDepth []*pb.Event

				for _, protoEvent := range queue {
					outputID := events.ID(protoEvent.Id)

					mapped := t.policyManager.GetDerivedEventMatchedRules(
						outputID, baseEventID, matchedRulesBitmap)

					// Direct-input detectors (consuming a non-derived event such as
					// sched_process_exec/exit, which are bootstrap-selected and dispatched to
					// detectors independent of policy matching) can leave the base bitmap
					// carrying only unrelated bits (e.g. the bootstrap rule), so the mapping
					// comes back empty. The output is itself a selected event, so seed it with
					// its own candidate rules and let matchPoliciesProto narrow by the output's
					// filters. Non-empty mappings (derived-event chains like
					// process_execute_failed) are left untouched.
					if bitwise.IsBitmapArrayEmpty(mapped) {
						mapped = t.policyManager.GetAllRulesBitmap(outputID)
					}

					// Create proto-native PipelineEvent (similar to derive stage)
					pipelineEvent := &events.PipelineEvent{
						Event:              nil, // proto-native, no trace.Event
						EventID:            outputID,
						Timestamp:          uint64(protoEvent.GetTimestamp().AsTime().UnixNano()),
						MatchedRulesBitmap: mapped,
						ProtoEvent:         protoEvent,
					}

					// Apply rule filtering to detector outputs (narrows by the output's filters)
					if !t.matchPoliciesProto(pipelineEvent) {
						continue // Skip events not matching any rule
					}

					// Dispatch to next level detectors FIRST (before sending to sink)
					// This allows detectors to clone the proto before sink mutates it
					nextOutputs, err := t.detectorEngine.DispatchToDetectors(ctx, protoEvent)
					if err != nil {
						t.handleError(err)
						// Still send current event even if dispatch fails
					}

					// Send to output (blocking - sink always consumes)
					out <- pipelineEvent

					nextDepth = append(nextDepth, nextOutputs...)
				}

				queue = nextDepth
			}

			// Safety check - log if max depth exceeded
			if len(queue) > 0 {
				t.detectorEngine.GetMetrics().ChainDepthExceeded.Inc()
				_ = t.stats.ErrorCount.Increment()
				logger.Errorw("Exceeded max detector chain depth",
					"max_depth", maxDetectorChainDepth,
					"remaining_events", len(queue))
			}
		}
	}()

	return out, errc
}

// sinkEvents is the event sink pipeline stage. For each received event, it goes through a
// series of printers that will print the event to the desired output. It also handles the
// event pool, returning the event to the pool after it is processed.
func (t *Tracee) sinkEvents(in <-chan *events.PipelineEvent) <-chan error {
	errc := make(chan error, 1)

	go func() {
		defer close(errc)

		for event := range in {
			if event == nil {
				continue // might happen during initialization (ctrl+c seg faults)
			}

			// Convert to protobuf once at the beginning of sink stage
			// ToProto() returns nil if event data is nil/invalid
			pbEvent := event.ToProto()
			if pbEvent == nil {
				t.eventsPool.Put(event)
				continue
			}

			// Is the event enabled?
			if !t.policyManager.IsEventEnabled(event.EventID) {
				// TODO: create metrics from dropped events
				t.eventsPool.Put(event)
				continue
			}

			// Only emit events the user explicitly selected (a SelectedByUser rule) and
			// that matched at least one rule. GetMatchedRulesInfo returns the matched
			// user-selected policy names; empty means only dependency rules matched (the
			// event is internal-only, e.g. a base event for a derivation) -> drop.
			// Use the PipelineEvent working bitmap (always set by matchPolicies/
			// matchPoliciesProto) rather than the embedded trace.Event field, which is
			// nil for proto-native detector-output events.
			matchedNames := t.policyManager.GetMatchedRulesInfo(event.EventID, event.MatchedRulesBitmap)
			if len(matchedNames) == 0 {
				t.eventsPool.Put(event)
				continue
			}

			// Populate the protobuf event with the names of the matched policies.
			if pbEvent.Policies == nil {
				pbEvent.Policies = &pb.Policies{}
			}
			pbEvent.Policies.Matched = matchedNames

			// Parse arguments for output formatting if enabled.
			if t.config.Output.DecodedData {
				err := events.ParseDataFields(pbEvent.Data, int(pbEvent.Id))
				if err != nil {
					t.handleError(err)
				}
			}

			if t.config.Output.FdPaths {
				// Use original timestamp from pipeline metadata for BPF map lookup
				err := events.ParseDataFieldsFDs(pbEvent.Data, event.Timestamp, t.FDArgPathMap)
				if err != nil {
					t.handleError(err)
				}
			}

			// Send the event to the streams.
			if t.streamsManager.HasSubscribers() {
				// Detach the slab from pool management - the stream takes ownership.
				// This prevents the slab from being recycled while the stream still
				// holds a reference to the proto event.
				pbEvent = event.DetachProto()
				// Translate event ID to external format for streams (external API boundary)
				pbEvent.Id = pb.EventId(events.TranslateEventID(int(pbEvent.Id)))
				// Route to streams by matched (user-selected) policy names - the rule model
				// has no per-policy integer id to build a bitmap from.
				t.streamsManager.Publish(pbEvent, matchedNames)
			}
			_ = t.stats.EventCount.Increment()
			t.eventsPool.Put(event)
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

// extractReturnValue extracts the returnValue argument from event arguments.
// It expects returnValue to be the last argument with type int64.
// Returns 0 if not found or if the type is incorrect.
func extractReturnValue(args []trace.Argument, eventName string) int {
	if len(args) == 0 {
		return 0
	}

	lastArg := args[len(args)-1]
	if lastArg.Name != "returnValue" {
		return 0
	}

	val, ok := lastArg.Value.(int64)
	if !ok {
		logger.Warnw("unexpected type for returnValue argument",
			"event", eventName,
			"expected", "int64",
			"actual", fmt.Sprintf("%T", lastArg.Value),
		)
		return 0
	}

	return int(val)
}

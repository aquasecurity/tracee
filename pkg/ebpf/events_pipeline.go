package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"strconv"
	"sync"
	"unsafe"

	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
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
func (t *Tracee) handleEvents(ctx context.Context) {
	logger.Debugw("Starting handleEvents goroutine")
	defer logger.Debugw("Stopped handleEvents goroutine")

	var errcList []<-chan error

	// Decode stage: events are read from the perf buffer and decoded into trace.Event type.

	eventsChan, errc := t.decodeEvents(ctx, t.eventsChannel)
	errcList = append(errcList, errc)

	// Cache stage: events go through a caching function.

	if t.config.Cache != nil {
		eventsChan, errc = t.queueEvents(ctx, eventsChan)
		errcList = append(errcList, errc)
	}

	// Sort stage: events go through a sorting function.

	if t.config.Output.EventsSorting {
		eventsChan, errc = t.eventsSorter.StartPipeline(ctx, eventsChan)
		errcList = append(errcList, errc)
	}

	// Process events stage: events go through a processing functions.

	eventsChan, errc = t.processEvents(ctx, eventsChan)
	errcList = append(errcList, errc)

	// Enrichment stage: container events are enriched with additional runtime data.

	if !t.config.NoContainersEnrich { // TODO: remove safe-guard soon.
		eventsChan, errc = t.enrichContainerEvents(ctx, eventsChan)
		errcList = append(errcList, errc)
	}

	// Derive events stage: events go through a derivation function.

	eventsChan, errc = t.deriveEvents(ctx, eventsChan)
	errcList = append(errcList, errc)

	// Engine events stage: events go through the signatures engine for detection.

	if t.config.EngineConfig.Enabled {
		eventsChan, errc = t.engineEvents(ctx, eventsChan)
		errcList = append(errcList, errc)
	}

	// Sink pipeline stage: events go through printers.

	errc = t.sinkEvents(ctx, eventsChan)
	errcList = append(errcList, errc)

	// Pipeline started. Waiting for pipeline to complete

	if err := t.WaitForPipeline(errcList...); err != nil {
		logger.Errorw("Pipeline", "error", err)
	}
}

// Under some circumstances, tracee-rules might be slower to consume events than
// tracee-ebpf is capable of generating them. This requires tracee-ebpf to deal with this
// possible lag, but, at the same, perf-buffer consumption can't be left behind (or
// important events coming from the kernel might be loss, causing detection misses).
//
// There are 3 variables connected to this issue:
//
// 1) perf buffer could be increased to hold very big amount of memory pages: The problem
// with this approach is that the requested space, to perf-buffer, through libbpf, has to
// be contiguous and it is almost impossible to get very big contiguous allocations
// through mmap after a node is running for some time.
//
// 2) raising the events channel buffer to hold a very big amount of events: The problem
// with this approach is that the overhead of dealing with that amount of buffers, in a
// golang channel, causes event losses as well. It means this is not enough to relief the
// pressure from kernel events into perf-buffer.
//
// 3) create an internal, to tracee-ebpf, buffer based on the node size.

// queueEvents is the cache pipeline stage. For each received event, it goes through a
// caching function that will enqueue the event into a queue. The queue is then de-queued
// by a different goroutine that will send the event down the pipeline.
func (t *Tracee) queueEvents(ctx context.Context, in <-chan *trace.Event) (chan *trace.Event, chan error) {
	out := make(chan *trace.Event, 10000)
	errc := make(chan error, 1)
	done := make(chan struct{}, 1)

	// receive and cache events (release pressure in the pipeline)
	go func() {
		for {
			select {
			case <-ctx.Done():
				done <- struct{}{}
				return
			case event := <-in:
				if event != nil {
					t.config.Cache.Enqueue(event) // may block if queue is full
				}
			}
		}
	}()

	// de-cache and send events (free cache space)
	go func() {
		defer close(out)
		defer close(errc)

		for {
			select {
			case <-done:
				return
			default:
				event := t.config.Cache.Dequeue() // may block if queue is empty
				if event != nil {
					out <- event
				}
			}
		}
	}()

	return out, errc
}

// decodeEvents is the event decoding pipeline stage. For each received event, it goes
// through a decoding function that will decode the event from its raw format into a
// trace.Event type.
func (t *Tracee) decodeEvents(outerCtx context.Context, sourceChan chan []byte) (<-chan *trace.Event, <-chan error) {
	out := make(chan *trace.Event, 10000)
	errc := make(chan error, 1)
	sysCompatTranslation := events.Core.IDs32ToIDs()
	go func() {
		defer close(out)
		defer close(errc)
		for dataRaw := range sourceChan {
			ebpfMsgDecoder := bufferdecoder.New(dataRaw)
			var ctx bufferdecoder.Context
			if err := ebpfMsgDecoder.DecodeContext(&ctx); err != nil {
				t.handleError(err)
				continue
			}
			var argnum uint8
			if err := ebpfMsgDecoder.DecodeUint8(&argnum); err != nil {
				t.handleError(err)
				continue
			}
			eventId := events.ID(ctx.EventID)
			if !events.Core.IsDefined(eventId) {
				t.handleError(errfmt.Errorf("failed to get configuration of event %d", eventId))
				continue
			}
			eventDefinition := events.Core.GetDefinitionByID(eventId)
			args := make([]trace.Argument, len(eventDefinition.GetParams()))
			err := ebpfMsgDecoder.DecodeArguments(args, int(argnum), eventDefinition, eventId)
			if err != nil {
				t.handleError(err)
				continue
			}

			// Add stack trace if needed
			var stackAddresses []uint64
			if t.config.Output.StackAddresses {
				stackAddresses = t.getStackAddresses(ctx.StackID)
			}

			containerInfo := t.containers.GetCgroupInfo(ctx.CgroupID).Container
			containerData := trace.Container{
				ID:          containerInfo.ContainerId,
				ImageName:   containerInfo.Image,
				ImageDigest: containerInfo.ImageDigest,
				Name:        containerInfo.Name,
			}
			kubernetesData := trace.Kubernetes{
				PodName:      containerInfo.Pod.Name,
				PodNamespace: containerInfo.Pod.Namespace,
				PodUID:       containerInfo.Pod.UID,
			}

			flags := parseContextFlags(containerData.ID, ctx.Flags)
			syscall := ""
			if ctx.Syscall != noSyscall {
				var err error
				syscall, err = parseSyscallID(int(ctx.Syscall), flags.IsCompat, sysCompatTranslation)
				if err != nil {
					logger.Debugw("Originated syscall parsing", "error", err)
				}
			}

			// get an event pointer from the pool
			evt := t.eventsPool.Get().(*trace.Event)

			// populate all the fields of the event used in this stage, and reset the rest

			evt.Timestamp = int(ctx.Ts)
			evt.ThreadStartTime = int(ctx.StartTime)
			evt.ProcessorID = int(ctx.ProcessorId)
			evt.ProcessID = int(ctx.Pid)
			evt.ThreadID = int(ctx.Tid)
			evt.ParentProcessID = int(ctx.Ppid)
			evt.HostProcessID = int(ctx.HostPid)
			evt.HostThreadID = int(ctx.HostTid)
			evt.HostParentProcessID = int(ctx.HostPpid)
			evt.UserID = int(ctx.Uid)
			evt.MountNS = int(ctx.MntID)
			evt.PIDNS = int(ctx.PidID)
			evt.ProcessName = string(bytes.TrimRight(ctx.Comm[:], "\x00"))
			evt.HostName = string(bytes.TrimRight(ctx.UtsName[:], "\x00"))
			evt.CgroupID = uint(ctx.CgroupID)
			evt.ContainerID = containerData.ID
			evt.Container = containerData
			evt.Kubernetes = kubernetesData
			evt.EventID = int(ctx.EventID)
			evt.EventName = eventDefinition.GetName()
			evt.MatchedPoliciesKernel = ctx.MatchedPolicies
			evt.MatchedPoliciesUser = 0
			evt.MatchedPolicies = []string{}
			evt.ArgsNum = int(argnum)
			evt.ReturnValue = int(ctx.Retval)
			evt.Args = args
			evt.StackAddresses = stackAddresses
			evt.ContextFlags = flags
			evt.Syscall = syscall
			evt.Metadata = nil
			evt.ThreadEntityId = utils.HashTaskID(ctx.HostTid, ctx.StartTime)
			evt.ProcessEntityId = utils.HashTaskID(ctx.HostPid, ctx.LeaderStartTime)
			evt.ParentEntityId = utils.HashTaskID(ctx.HostPpid, ctx.ParentStartTime)

			// If there aren't any policies that need filtering in userland, tracee **may** skip
			// this event, as long as there aren't any derivatives or signatures that depend on it.
			// Some base events (derivative and signatures) might not have set related policy bit,
			// thus the need to continue with those within the pipeline.
			if t.matchPolicies(evt) == 0 {
				_, hasDerivation := t.eventDerivations[eventId]
				_, hasSignature := t.eventSignatures[eventId]

				if !hasDerivation && !hasSignature {
					_ = t.stats.EventsFiltered.Increment()
					t.eventsPool.Put(evt)
					continue
				}
			}

			select {
			case out <- evt:
			case <-outerCtx.Done():
				return
			}
		}
	}()
	return out, errc
}

// matchPolicies does the userland filtering (policy matching) for events. It iterates through all
// existing policies, that were set by the kernel in the event bitmap. Some of those policies might
// not match the event after userland filters are applied. In those cases, the policy bit is cleared
// (so the event is "filtered" for that policy). This may be called in different stages of the
// pipeline (decode, derive, engine).
func (t *Tracee) matchPolicies(event *trace.Event) uint64 {
	eventID := events.ID(event.EventID)
	bitmap := event.MatchedPoliciesKernel

	// Short circuit if there are no policies in userland that need filtering.
	if bitmap&t.config.Policies.FilterableInUserland() == 0 {
		event.MatchedPoliciesUser = bitmap // store untoched bitmap to be used in sink stage
		return bitmap
	}

	for p := range t.config.Policies.FilterableInUserlandMap() { // range through each userland filterable policy
		// Policy ID is the bit offset in the bitmap.
		bitOffset := uint(p.ID)

		if !utils.HasBit(bitmap, bitOffset) { // event does not match this policy
			continue
		}

		// The event might have this policy bit set, but the policy might not have this
		// event ID. This happens whenever the event submitted by the kernel is going to
		// derive an event that this policy is interested in. In this case, don't do
		// anything and let the derivation stage handle this event.
		_, ok := p.EventsToTrace[eventID]
		if !ok {
			continue
		}

		//
		// Do the userland filtering
		//

		// 1. event context filters
		if !p.ContextFilter.Filter(*event) {
			utils.ClearBit(&bitmap, bitOffset)
			continue
		}

		// 2. event return value filters
		if !p.RetFilter.Filter(eventID, int64(event.ReturnValue)) {
			utils.ClearBit(&bitmap, bitOffset)
			continue
		}

		// 3. event arguments filters
		if !p.ArgFilter.Filter(eventID, event.Args) {
			utils.ClearBit(&bitmap, bitOffset)
			continue
		}

		//
		// Do the userland filtering for filters with global ranges
		//

		if p.UIDFilter.Enabled() {
			//
			// An event with a matched policy for global min/max range might not match all
			// policies with UID and PID filters with different min/max ranges, e.g.:
			//
			//   policy 59: comm=who, pid>100 and pid<1257738
			//   policy 30: comm=who, pid>502000 and pid<505000
			//
			// For kernel filtering, the flags from the example would compute:
			//
			// pid_max = 1257738
			// pid_min = 100
			//
			// Userland filtering needs to refine the bitmap to match the policies: A
			// "who" command with pid 150 is a match ONLY for the policy 59 in this
			// example.
			//
			// Clear the policy bit if the event UID is not in THIS policy UID min/max range:
			if !p.UIDFilter.InMinMaxRange(uint32(event.UserID)) {
				utils.ClearBit(&bitmap, bitOffset)
				continue
			}
		}

		if p.PIDFilter.Enabled() {
			//
			// The same happens for the global PID min/max range. Clear the policy bit if
			// the event PID is not in THIS policy PID min/max range.
			//
			if !p.PIDFilter.InMinMaxRange(uint32(event.HostProcessID)) {
				utils.ClearBit(&bitmap, bitOffset)
				continue
			}
		}
	}

	event.MatchedPoliciesUser = bitmap // store filtered bitmap to be used in sink stage

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

// parseSyscallID returns the syscall name from its ID, taking into account architecture
// and 32bit/64bit modes. It also returns an error if the syscall ID is not found in the
// events definition.
func parseSyscallID(syscallID int, isCompat bool, compatTranslationMap map[events.ID]events.ID) (string, error) {
	id := events.ID(syscallID)
	if !isCompat {
		if !events.Core.IsDefined(id) {
			return "", errfmt.Errorf("no syscall event with syscall id %d", syscallID)
		}
		return events.Core.GetDefinitionByID(id).GetName(), nil
	}
	if id, ok := compatTranslationMap[events.ID(syscallID)]; ok {
		// should never happen (map should be initialized from events definition)
		if !events.Core.IsDefined(id) {
			return "", errfmt.Errorf(
				"no syscall event with compat syscall id %d, translated to ID %d", syscallID, id,
			)
		}
		return events.Core.GetDefinitionByID(id).GetName(), nil
	}
	return "", errfmt.Errorf("no syscall event with compat syscall id %d", syscallID)
}

// processEvents is the event processing pipeline stage. For each received event, it goes
// through all event processors and check if there is any internal processing needed for
// that event type.  It also clears policy bits for out-of-order container related events
// (after the processing logic). This stage also starts some logic that will be used by
// the processing logic in subsequent events.
func (t *Tracee) processEvents(ctx context.Context, in <-chan *trace.Event) (
	<-chan *trace.Event, <-chan error,
) {
	out := make(chan *trace.Event, 10000)
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
			policiesWithContainerFilter := t.config.Policies.ContainerFilterEnabled()

			// Filter out events that don't have a container ID from all the policies that
			// have container filters. This will guarantee that any of those policies
			// won't get matched by this event. This situation might happen if the events
			// from a recently created container appear BEFORE the initial cgroup_mkdir of
			// that container root directory.  This could be solved by sorting the events
			// by a monotonic timestamp, for example, but sorting might not always be
			// enabled, so, in those cases, ignore the event IF the event is not a
			// cgroup_mkdir or cgroup_rmdir.

			if policiesWithContainerFilter > 0 && event.Container.ID == "" {
				eventId := events.ID(event.EventID)

				// never skip cgroup_{mkdir,rmdir}: container_{create,remove} events need it
				if eventId == events.CgroupMkdir || eventId == events.CgroupRmdir {
					goto sendEvent
				}

				logger.Debugw("False container positive", "event.Timestamp", event.Timestamp,
					"eventId", eventId)

				// remove event from the policies with container filters
				utils.ClearBits(&event.MatchedPoliciesKernel, policiesWithContainerFilter)
				utils.ClearBits(&event.MatchedPoliciesUser, policiesWithContainerFilter)

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
func (t *Tracee) deriveEvents(ctx context.Context, in <-chan *trace.Event) (
	<-chan *trace.Event, <-chan error,
) {
	out := make(chan *trace.Event)
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

				// Get a copy of our event before sending it down the pipeline. This is
				// needed because later modification of the event (in particular of the
				// matched policies) can affect the derivation and later pipeline logic
				// acting on the derived event.

				eventCopy := *event
				out <- event

				// Note: event is being derived before any of its args are parsed.
				derivatives, errors := t.eventDerivations.DeriveEvent(eventCopy)

				for _, err := range errors {
					t.handleError(err)
				}

				for i := range derivatives {
					// Skip events that dont work with filtering due to missing types
					// being handled (https://github.com/aquasecurity/tracee/issues/2486)
					switch events.ID(derivatives[i].EventID) {
					case events.SymbolsLoaded:
					case events.SharedObjectLoaded:
					case events.PrintMemDump:
					default:
						// Derived events might need filtering as well
						if t.matchPolicies(&derivatives[i]) == 0 {
							_ = t.stats.EventsFiltered.Increment()
							continue
						}
					}

					// Passing "derivative" variable here will make the ptr address always
					// be the same as the last item. This makes the printer to print 2 or
					// 3 times the last event, instead of printing all derived events
					// (when there are more than one).
					out <- &derivatives[i]
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

			// Is the event enabled for the policies or globally?
			if !t.policyManager.IsEnabled(event.MatchedPoliciesUser, events.ID(event.EventID)) {
				// TODO: create metrics from dropped events
				t.eventsPool.Put(event)
				continue
			}

			// Only emit events requested by the user and matched by at least one policy.
			id := events.ID(event.EventID)
			event.MatchedPoliciesUser &= t.eventsState[id].Emit
			if event.MatchedPoliciesUser == 0 {
				t.eventsPool.Put(event)
				continue
			}

			// Populate the event with the names of the matched policies.
			event.MatchedPolicies = t.config.Policies.MatchedNames(event.MatchedPoliciesUser)

			// Parse args here if the rule engine is not enabled (parsed there if it is).
			if !t.config.EngineConfig.Enabled {
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
	stackBytes, err := t.StackAddressesMap.GetValue(unsafe.Pointer(&stackID))
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
	_ = t.StackAddressesMap.DeleteKey(unsafe.Pointer(&stackID))

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

// parseArguments parses the arguments of the event. It must happen before the signatures
// are evaluated. For the new experience (cmd/tracee), it needs to happen in the the
// "events_engine" stage of the pipeline. For the old experience (cmd/tracee-ebpf &&
// cmd/tracee-rules), it happens on the "sink" stage of the pipeline (close to the
// printers).
func (t *Tracee) parseArguments(e *trace.Event) error {
	if t.config.Output.ParseArguments {
		err := events.ParseArgs(e)
		if err != nil {
			return errfmt.WrapError(err)
		}
		if t.config.Output.ParseArgumentsFDs {
			return events.ParseArgsFDs(e, t.FDArgPathMap)
		}
	}

	return nil
}

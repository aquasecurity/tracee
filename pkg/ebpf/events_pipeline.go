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

// Max depth of each stack trace to track
// Matches 'MAX_STACK_DEPTH' in eBPF code
const maxStackDepth int = 20

// Matches 'NO_SYSCALL' in eBPF code
const noSyscall int32 = -1

// handleEvents is a high-level function that starts all operations related to events processing
func (t *Tracee) handleEvents(ctx context.Context) {
	var errcList []<-chan error

	// Source pipeline stage.
	eventsChan, errc := t.decodeEvents(ctx, t.eventsChannel)
	errcList = append(errcList, errc)

	if t.config.Cache != nil {
		eventsChan, errc = t.queueEvents(ctx, eventsChan)
		errcList = append(errcList, errc)
	}

	if t.config.Output.EventsSorting {
		eventsChan, errc = t.eventsSorter.StartPipeline(ctx, eventsChan)
		errcList = append(errcList, errc)
	}

	// Process events stage
	// in this stage we perform event specific logic
	eventsChan, errc = t.processEvents(ctx, eventsChan)
	errcList = append(errcList, errc)

	// Enrichment stage
	// In this stage container events are enriched with additional runtime data
	// Events may be enriched in the initial decode state if the enrichment data has been stored in the Containers structure
	// In that case, this pipeline stage will be quickly skipped
	// This is done in a separate stage to ensure enrichment is non blocking (since container runtime calls may timeout and block the pipeline otherwise)
	if t.config.ContainersEnrich {
		eventsChan, errc = t.enrichContainerEvents(ctx, eventsChan)
		errcList = append(errcList, errc)
	}

	// Derive events stage
	// In this stage events go through a derivation function
	eventsChan, errc = t.deriveEvents(ctx, eventsChan)
	errcList = append(errcList, errc)

	// Engine events stage
	// In this stage events go through a signatures match
	if t.config.EngineConfig.Enabled {
		eventsChan, errc = t.engineEvents(ctx, eventsChan)
		errcList = append(errcList, errc)
	}

	// Sink pipeline stage.
	errc = t.sinkEvents(ctx, eventsChan)
	errcList = append(errcList, errc)

	// Pipeline started. Waiting for pipeline to complete
	if err := t.WaitForPipeline(errcList...); err != nil {
		logger.Errorw("Pipeline", "error", err)
	}
}

// Under some circumstances, tracee-rules might be slower to consume events
// than tracee-ebpf is capable of generating them. This requires
// tracee-ebpf to deal with this possible lag, but, at the same,
// perf-buffer consumption can't be left behind (or important events coming
// from the kernel might be loss, causing detection misses).
//
// There are 3 variables connected to this issue:
//
// 1) perf buffer could be increased to hold very big amount of memory
//    pages: The problem with this approach is that the requested space,
//    to perf-buffer, through libbpf, has to be contiguous and it is almost
//    impossible to get very big contiguous allocations through mmap after
//    a node is running for some time.
//
// 2) raising the events channel buffer to hold a very big amount of
//    events: The problem with this approach is that the overhead of
//    dealing with that amount of buffers, in a golang channel, causes
//    event losses as well. It means this is not enough to relief the
//    pressure from kernel events into perf-buffer.
//
// 3) create an internal, to tracee-ebpf, buffer based on the node size.

// queueEvents implements an internal FIFO queue for caching events
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

// decodeEvents read the events received from the BPF programs and parse it into trace.Event type
func (t *Tracee) decodeEvents(outerCtx context.Context, sourceChan chan []byte) (<-chan *trace.Event, <-chan error) {
	out := make(chan *trace.Event, 10000)
	errc := make(chan error, 1)
	sysCompatTranslation := events.Definitions.IDs32ToIDs()
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
			eventId := events.ID(ctx.EventID)
			eventDefinition, ok := events.Definitions.GetSafe(eventId)
			if !ok {
				t.handleError(errfmt.Errorf("failed to get configuration of event %d", eventId))
				continue
			}

			args := make([]trace.Argument, len(eventDefinition.Params))
			for i := 0; i < int(ctx.Argnum); i++ {
				idx, arg, err := bufferdecoder.ReadArgFromBuff(
					eventId,
					ebpfMsgDecoder,
					eventDefinition.Params,
				)
				if err != nil {
					t.handleError(errfmt.Errorf("failed to read argument %d of event %s: %v", i, eventDefinition.Name, err))
					continue
				}
				if args[idx].Value != nil {
					t.handleError(errfmt.Errorf("read more than one instance of argument %s of event %s. Saved value: %v. New value: %v", arg.Name, eventDefinition.Name, args[idx].Value, arg.Value))
				}
				args[idx] = arg
			}
			// Fill missing arguments metadata
			for i := 0; i < len(eventDefinition.Params); i++ {
				if args[i].Value == nil {
					args[i].ArgMeta = eventDefinition.Params[i]
				}
			}

			// Add stack trace if needed
			var StackAddresses []uint64
			if t.config.Output.StackAddresses {
				StackAddresses, _ = t.getStackAddresses(ctx.StackID)
			}

			// Currently, the timestamp received from the bpf code is of the monotonic clock.
			// Todo: The monotonic clock doesn't take into account system sleep time.
			// Starting from kernel 5.7, we can get the timestamp relative to the system boot time instead which is preferable.
			if t.config.Output.RelativeTime {
				// To get the monotonic time since tracee was started, we have to subtract the start time from the timestamp.
				ctx.Ts -= t.startTime
				ctx.StartTime -= t.startTime
			} else {
				// To get the current ("wall") time, we add the boot time into it.
				ctx.Ts += t.bootTime
				ctx.StartTime += t.bootTime
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

			flags := parseContextFlags(ctx.Flags)
			syscall := ""
			if ctx.Syscall != noSyscall {
				var err error
				syscall, err = parseSyscallID(int(ctx.Syscall), flags.IsCompat, sysCompatTranslation)
				if err != nil {
					logger.Debugw("Originated syscall parsing", "error", err)
				}
			}

			evt := trace.Event{
				Timestamp:           int(ctx.Ts),
				ThreadStartTime:     int(ctx.StartTime),
				ProcessorID:         int(ctx.ProcessorId),
				ProcessID:           int(ctx.Pid),
				ThreadID:            int(ctx.Tid),
				ParentProcessID:     int(ctx.Ppid),
				HostProcessID:       int(ctx.HostPid),
				HostThreadID:        int(ctx.HostTid),
				HostParentProcessID: int(ctx.HostPpid),
				UserID:              int(ctx.Uid),
				MountNS:             int(ctx.MntID),
				PIDNS:               int(ctx.PidID),
				ProcessName:         string(bytes.TrimRight(ctx.Comm[:], "\x00")),
				HostName:            string(bytes.TrimRight(ctx.UtsName[:], "\x00")),
				CgroupID:            uint(ctx.CgroupID),
				Container:           containerData,
				Kubernetes:          kubernetesData,
				EventID:             int(ctx.EventID),
				EventName:           eventDefinition.Name,
				MatchedPolicies:     ctx.MatchedPolicies,
				ArgsNum:             int(ctx.Argnum),
				ReturnValue:         int(ctx.Retval),
				Args:                args,
				StackAddresses:      StackAddresses,
				ContextFlags:        flags,
				Syscall:             syscall,
			}

			if !t.shouldProcessEvent(&evt) {
				_ = t.stats.EventsFiltered.Increment()
				// we can stop processing the event if it doesn't have derivatives.
				// otherwise, since it has MatchedPolicies==0 it won't be emitted later anyway.
				if _, ok := t.eventDerivations[eventId]; !ok {
					continue
				}
			}

			select {
			case out <- &evt:
			case <-outerCtx.Done():
				return
			}
		}
	}()
	return out, errc
}

// computePolicies iterates through the policies that do the filtering in user space, checking whether an event should be considered.
// If it should not, it sets the respective offset to 0.
// Finally it returns computed policies and the names of the policies that matched.
func (t *Tracee) computePolicies(event *trace.Event) (uint64, []string) {
	eventID := events.ID(event.EventID)
	matchedPolicies := event.MatchedPolicies
	matchedPoliciesNames := []string{}

	for p := range t.config.Policies.Map() {
		bitOffset := uint(p.ID)

		// Events submitted with matching policies.
		// The policy must have its bit cleared when it does not match.
		if !utils.HasBit(matchedPolicies, bitOffset) {
			continue
		}

		if !p.ContextFilter.Filter(*event) {
			utils.ClearBit(&matchedPolicies, bitOffset)
			continue
		}

		if !p.RetFilter.Filter(eventID, int64(event.ReturnValue)) {
			utils.ClearBit(&matchedPolicies, bitOffset)
			continue
		}

		if !p.ArgFilter.Filter(eventID, event.Args) {
			utils.ClearBit(&matchedPolicies, bitOffset)
			continue
		}

		// An event with a matched policy for global min/max range might not match
		// all policies with UID and PID filters with different min/max ranges.
		//
		// e.g.: -f 59:comm=who -f '59:pid>100' -f '59:pid<1257738' \
		//       -f 30:comm=who -f '30:pid>502000' -f '30:pid<505000'
		//
		// For kernel filtering the flags above would compute
		//
		// pid_max = 1257738
		// pid_min = 100
		//
		// So a who command with pid 150 is a match only for the policy 59

		if p.UIDFilter.Enabled() &&
			!p.UIDFilter.InMinMaxRange(uint32(event.UserID)) {
			utils.ClearBit(&matchedPolicies, bitOffset)
			continue
		}

		if p.PIDFilter.Enabled() &&
			!p.PIDFilter.InMinMaxRange(uint32(event.HostProcessID)) {
			utils.ClearBit(&matchedPolicies, bitOffset)
			continue
		}

		// as we reached here, the policy matched
		matchedPoliciesNames = append(matchedPoliciesNames, p.Name)
	}

	return matchedPolicies, matchedPoliciesNames
}

// shouldProcessEvent decides whether or not to drop an event before further processing it
func (t *Tracee) shouldProcessEvent(event *trace.Event) bool {
	// As we don't do all the filtering on the ebpf side, we have to update MatchedPolicies
	event.MatchedPolicies, event.MatchedPoliciesNames = t.computePolicies(event)
	return event.MatchedPolicies != 0
}

func parseContextFlags(flags uint32) trace.ContextFlags {
	const (
		ContainerStartFlag = 1 << iota
		IsCompatFlag
	)
	return trace.ContextFlags{
		ContainerStarted: (flags & ContainerStartFlag) != 0,
		IsCompat:         (flags & IsCompatFlag) != 0,
	}
}

// Get the syscall name from its ID, taking into account architecture and 32bit/64bit modes
func parseSyscallID(syscallID int, isCompat bool, compatTranslationMap map[events.ID]events.ID) (string, error) {
	if !isCompat {
		def, ok := events.Definitions.GetSafe(events.ID(syscallID))
		if ok {
			return def.Name, nil
		} else {
			return "", errfmt.Errorf("no syscall event with syscall id %d", syscallID)
		}
	} else {
		id, ok := compatTranslationMap[events.ID(syscallID)]
		if ok {
			def, ok := events.Definitions.GetSafe(id)
			if ok {
				return def.Name, nil
			} else { // Should never happen, as the translation map should be initialized from events.Definition
				return "", errfmt.Errorf("no syscall event with compat syscall id %d, translated to ID %d", syscallID, id)
			}
		} else {
			return "", errfmt.Errorf("no syscall event with compat syscall id %d", syscallID)
		}
	}
}

func (t *Tracee) processEvents(ctx context.Context, in <-chan *trace.Event) (<-chan *trace.Event, <-chan error) {
	out := make(chan *trace.Event, 10000)
	errc := make(chan error, 1)
	go func() {
		defer close(out)
		defer close(errc)
		for event := range in {
			errs := t.processEvent(event)
			if len(errs) > 0 {
				for _, err := range errs {
					t.handleError(err)
				}
				continue
			}

			// store the atomic read
			policiesWithContainerFilter := t.config.Policies.ContainerFilterEnabled()
			if policiesWithContainerFilter > 0 && event.Container.ID == "" {
				// Don't trace false container positives -
				// a container filter is set by the user, but this event wasn't originated in a container.
				// Although kernel filters shouldn't submit such events, we do this check to be on the safe side.
				// For example, it might be that a new cgroup was created, and not by a container runtime,
				// while we still didn't processed the cgroup_mkdir event and removed the cgroupid from the bpf container map.
				eventId := events.ID(event.EventID)

				// don't skip cgroup_mkdir and cgroup_rmdir so we can derive container_create and container_remove events
				if eventId != events.CgroupMkdir && eventId != events.CgroupRmdir {
					logger.Debugw("False container positive", "event.Timestamp", event.Timestamp, "eventId", eventId)

					// filter container policies out
					utils.ClearBits(&event.MatchedPolicies, policiesWithContainerFilter)
					if event.MatchedPolicies == 0 {
						continue
					}
				}
			}

			select {
			case out <- event:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, errc
}

// deriveEvents is the derivation pipeline stage
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

				// Get a copy of our event before sending it down the pipeline.
				// This is needed because later modification of the event (in
				// particular of the matched policies) can affect the derivation
				// and later pipeline logic acting on the derived event.
				eventCopy := *event
				out <- event

				// Derive event before parse its arguments
				derivatives, errors := t.eventDerivations.DeriveEvent(eventCopy)

				for _, err := range errors {
					t.handleError(err)
				}

				for i, derivative := range derivatives {
					// Skip events that don't work well with filtering due to
					// missing types being handled and similar reasons.
					// https://github.com/aquasecurity/tracee/issues/2486
					switch events.ID(derivative.EventID) {
					case events.SymbolsLoaded:
					case events.SharedObjectLoaded:
					case events.PrintMemDump:
					default:
						// Derived events might need filtering as well
						if !t.shouldProcessEvent(&derivative) {
							_ = t.stats.EventsFiltered.Increment()
							continue
						}
					}

					// Passing "derivative" variable here will make the ptr
					// address always be the same as the last item. This makes
					// the printer to print 2 or 3 times the last event, instead
					// of printing all derived events (when there are more than
					// one).
					out <- &derivatives[i]
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	return out, errc
}

func (t *Tracee) sinkEvents(ctx context.Context, in <-chan *trace.Event) <-chan error {
	errc := make(chan error, 1)

	go func() {
		defer close(errc)
		for event := range in {
			// Only emit events requested by the user
			id := events.ID(event.EventID)
			event.MatchedPolicies &= t.events[id].emit
			if event.MatchedPolicies == 0 {
				continue
			}

			// if the rule engine is not enabled, we parse arguments here before sending
			// the output to the printers
			if !t.config.EngineConfig.Enabled {
				err := t.parseArguments(event)
				if err != nil {
					t.handleError(err)
				}
			}

			select {
			case t.config.ChanEvents <- *event:
				_ = t.stats.EventCount.Increment()
				event = nil
			case <-ctx.Done():
				return
			}
		}
	}()

	return errc
}

func (t *Tracee) getStackAddresses(StackID uint32) ([]uint64, error) {
	StackAddresses := make([]uint64, maxStackDepth)
	stackFrameSize := (strconv.IntSize / 8)

	// Lookup the StackID in the map
	// The ID could have aged out of the Map, as it only holds a finite number of
	// Stack IDs in it's Map
	stackBytes, err := t.StackAddressesMap.GetValue(unsafe.Pointer(&StackID))
	if err != nil {
		return StackAddresses[0:0], nil
	}

	stackCounter := 0
	for i := 0; i < len(stackBytes); i += stackFrameSize {
		StackAddresses[stackCounter] = 0
		stackAddr := binary.LittleEndian.Uint64(stackBytes[i : i+stackFrameSize])
		if stackAddr == 0 {
			break
		}
		StackAddresses[stackCounter] = stackAddr
		stackCounter++
	}

	// Attempt to remove the ID from the map so we don't fill it up
	// But if this fails continue on
	_ = t.StackAddressesMap.DeleteKey(unsafe.Pointer(&StackID))

	return StackAddresses[0:stackCounter], nil
}

// WaitForPipeline waits for results from all error channels.
func (t *Tracee) WaitForPipeline(errs ...<-chan error) error {
	errc := MergeErrors(errs...)
	for err := range errc {
		t.handleError(err)
	}
	return nil
}

// MergeErrors merges multiple channels of errors.
// Based on https://blog.golang.org/pipelines.
func MergeErrors(cs ...<-chan error) <-chan error {
	var wg sync.WaitGroup
	// We must ensure that the output channel has the capacity to hold as many errors
	// as there are error channels. This will ensure that it never blocks, even
	// if WaitForPipeline returns early.
	out := make(chan error, len(cs))

	// Start an output goroutine for each input channel in cs.  output
	// copies values from c to out until c is closed, then calls wg.Done.
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

	// Start a goroutine to close out once all the output goroutines are
	// done.  This must start after the wg.Add call.
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

// parseArguments must happen before signatures are evaluated.
// For the new experience (cmd/tracee), it needs to happen in the the events_engine stage of the pipeline.
// For the old experience (cmd/tracee-ebpf && cmd/tracee-rules), it happens on the sink stage of the pipeline.
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

package tracee

import (
	"bytes"
	gocontext "context"
	"encoding/binary"
	"fmt"
	"strconv"
	"sync"
	"unsafe"

	"github.com/aquasecurity/tracee/pkg/external"
)

// Max depth of each stack trace to track
// Matches 'MAX_STACK_DEPTH' in eBPF code
const maxStackDepth int = 20

// context struct contains common metadata that is collected for all types of events
// it is used to unmarshal binary data and therefore should match (bit by bit) to the `context_t` struct in the ebpf code.
// NOTE: Integers want to be aligned in memory, so if changing the format of this struct
// keep the 1-byte 'Argnum' as the final parameter before the padding (if padding is needed).
type context struct {
	Ts       uint64
	CgroupID uint64
	Pid      uint32
	Tid      uint32
	Ppid     uint32
	HostPid  uint32
	HostTid  uint32
	HostPpid uint32
	Uid      uint32
	MntID    uint32
	PidID    uint32
	Comm     [16]byte
	UtsName  [16]byte
	EventID  int32
	Retval   int64
	StackID  uint32
	Argnum   uint8
	_        [3]byte //padding
}

// handleEvents is a high-level function that starts all operations related to events processing
func (t *Tracee) handleEvents(ctx gocontext.Context) {
	var errcList []<-chan error

	// Source pipeline stage.
	eventsChan, errc := t.decodeEvents(ctx)
	errcList = append(errcList, errc)

	// Sink pipeline stage.
	errc = t.processEvents(ctx, eventsChan)
	errcList = append(errcList, errc)

	// Pipeline started. Waiting for pipeline to complete
	t.WaitForPipeline(errcList...)
}

// decodeEvents read the events received from the BPF programs and parse it into external.Event type
func (t *Tracee) decodeEvents(outerCtx gocontext.Context) (<-chan *external.Event, <-chan error) {
	out := make(chan *external.Event)
	errc := make(chan error, 1)
	go func() {
		defer close(out)
		defer close(errc)
		for dataRaw := range t.eventsChannel {
			dataBuff := bytes.NewBuffer(dataRaw)
			var ctx context
			err := binary.Read(dataBuff, binary.LittleEndian, &ctx)
			if err != nil {
				t.handleError(err)
				continue
			}

			eventDefinition, ok := EventsDefinitions[ctx.EventID]
			if !ok {
				t.handleError(fmt.Errorf("failed to get configuration of event %d", ctx.EventID))
				continue
			}

			args := make([]external.Argument, 0, ctx.Argnum)

			for i := 0; i < int(ctx.Argnum); i++ {
				argMeta, argVal, err := readArgFromBuff(dataBuff, eventDefinition.Params)
				if err != nil {
					t.handleError(fmt.Errorf("failed to read argument %d of event %s: %v", i, eventDefinition.Name, err))
					continue
				}

				args = append(args, external.Argument{ArgMeta: argMeta, Value: argVal})
			}

			if !t.shouldProcessEvent(&ctx, args) {
				continue
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
				// To get the monotonic time since tracee was started, we have to substract the start time from the timestamp.
				ctx.Ts -= t.startTime
			} else {
				// To get the current ("wall") time, we add the boot time into it.
				ctx.Ts += t.bootTime
			}

			evt := external.Event{
				Timestamp:           int(ctx.Ts),
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
				ContainerID:         t.containers.GetCgroupInfo(ctx.CgroupID).ContainerId,
				EventID:             int(ctx.EventID),
				EventName:           eventDefinition.Name,
				ArgsNum:             int(ctx.Argnum),
				ReturnValue:         int(ctx.Retval),
				Args:                args,
				StackAddresses:      StackAddresses,
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

func (t *Tracee) processEvents(ctx gocontext.Context, in <-chan *external.Event) <-chan error {
	errc := make(chan error, 1)
	go func() {
		defer close(errc)
		for event := range in {
			err := t.processEvent(event)
			if err != nil {
				t.handleError(err)
				continue
			}

			if (t.config.Filter.ContFilter.Enabled || t.config.Filter.NewContFilter.Enabled) && event.ContainerID == "" {
				// Don't trace false container positives -
				// a container filter is set by the user, but this event wasn't originated in a container.
				// Although kernel filters shouldn't submit such events, we do this check to be on the safe side.
				// For example, it might be that a new cgroup was created, and not by a container runtime,
				// while we still didn't processed the cgroup_mkdir event and removed the cgroupid from the bpf container map.
				// Note: this check should be placed after processEvent() so cgroup_mkdir event is processed
				continue
			}

			// Derive event before parsing its arguments
			derivatives := t.deriveEvent(*event)

			// Only emit events requested by the user
			if t.eventsToTrace[int32(event.EventID)] {
				if t.config.Output.ParseArguments {
					err = t.parseArgs(event)
					if err != nil {
						t.handleError(err)
						continue
					}
				}

				select {
				case t.config.ChanEvents <- *event:
					t.stats.eventCounter.Increment()
				case <-ctx.Done():
					return
				}
			}

			for _, derivative := range derivatives {
				select {
				case t.config.ChanEvents <- derivative:
					t.stats.eventCounter.Increment()
				case <-ctx.Done():
					return
				}
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
	t.stats.errorCounter.Increment()
	t.config.ChanErrors <- err
}

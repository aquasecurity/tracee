package tracee

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
	"sync"
	"unsafe"

	"github.com/aquasecurity/tracee/tracee-ebpf/external"
)

func (t *Tracee) runEventPipeline(done <-chan struct{}) error {
	var errcList []<-chan error

	// Source pipeline stage.
	rawEventChan, errc, err := t.decodeRawEvent(done)
	if err != nil {
		return err
	}
	errcList = append(errcList, errc)

	processedEventChan, errc, err := t.processRawEvent(done, rawEventChan)
	if err != nil {
		return err
	}
	errcList = append(errcList, errc)

	errc, err = t.emitEvent(done, processedEventChan)
	if err != nil {
		return err
	}
	errcList = append(errcList, errc)

	// Pipeline started. Waiting for pipeline to complete
	return t.WaitForPipeline(errcList...)
}

type RawEvent struct {
	Ctx      context
	Args     map[string]interface{}
	ArgMetas []external.ArgMeta
}

// context struct contains common metadata that is collected for all types of events
// it is used to unmarshal binary data and therefore should match (bit by bit) to the `context_t` struct in the ebpf code.
// NOTE: Integers want to be aligned in memory, so if changing the format of this struct
// keep the 1-byte 'Argnum' as the final parameter before the padding (if padding is needed).
type context struct {
	Ts       uint64
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
	ContID   [16]byte
	EventID  int32
	Retval   int64
	StackID  uint32
	Argnum   uint8
	_        [3]byte //padding
}

func (t *Tracee) decodeRawEvent(done <-chan struct{}) (<-chan RawEvent, <-chan error, error) {
	out := make(chan RawEvent)
	errc := make(chan error, 1)
	go func() {
		defer close(out)
		defer close(errc)
		for dataRaw := range t.eventsChannel {
			dataBuff := bytes.NewBuffer(dataRaw)
			var ctx context
			err := binary.Read(dataBuff, binary.LittleEndian, &ctx)
			if err != nil {
				errc <- err
				continue
			}

			rawEvent := RawEvent{
				Ctx:      ctx,
				Args:     make(map[string]interface{}, ctx.Argnum),
				ArgMetas: make([]external.ArgMeta, ctx.Argnum),
			}

			params := EventsIDToParams[ctx.EventID]
			if params == nil {
				errc <- fmt.Errorf("failed to get parameters of event %d", ctx.EventID)
				continue
			}

			for i := 0; i < int(ctx.Argnum); i++ {
				argMeta, argVal, err := readArgFromBuff(dataBuff, params)
				if err != nil {
					errc <- fmt.Errorf("failed to read argument %d of event %d: %v", i, ctx.EventID, err)
					continue
				}

				rawEvent.Args[argMeta.Name] = argVal
				rawEvent.ArgMetas[i] = argMeta
			}

			select {
			case <-done:
				return
			case out <- rawEvent:
			}
		}
	}()
	return out, errc, nil
}

func (t *Tracee) processRawEvent(done <-chan struct{}, in <-chan RawEvent) (<-chan RawEvent, <-chan error, error) {
	out := make(chan RawEvent)
	errc := make(chan error, 1)
	go func() {
		defer close(out)
		defer close(errc)
		for rawEvent := range in {
			if !t.shouldProcessEvent(rawEvent) {
				continue
			}
			err := t.processEvent(&rawEvent.Ctx, rawEvent.Args)
			if err != nil {
				errc <- err
				continue
			}
			select {
			case <-done:
				return
			case out <- rawEvent:
			}
		}
	}()
	return out, errc, nil
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

func newEvent(ctx context, argMetas []external.ArgMeta, args map[string]interface{}, StackAddresses []uint64) (external.Event, error) {
	e := external.Event{
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
		ContainerID:         string(bytes.TrimRight(ctx.ContID[:], "\x00")),
		EventID:             int(ctx.EventID),
		EventName:           EventsIDToEvent[int32(ctx.EventID)].Name,
		ArgsNum:             int(ctx.Argnum),
		ReturnValue:         int(ctx.Retval),
		Args:                make([]external.Argument, 0, len(args)),
		StackAddresses:      StackAddresses,
	}
	for _, meta := range argMetas {
		e.Args = append(e.Args, external.Argument{
			ArgMeta: meta,
			Value:   args[meta.Name],
		})
	}
	return e, nil
}

func (t *Tracee) emitEvent(done <-chan struct{}, in <-chan RawEvent) (<-chan error, error) {
	errc := make(chan error, 1)
	go func() {
		defer close(errc)
		for rawEvent := range in {
			if !t.shouldEmitEvent(rawEvent) {
				continue
			}
			err := t.prepareArgs(&rawEvent.Ctx, rawEvent.Args)
			if err != nil {
				errc <- err
				continue
			}

			// Add stack trace if needed
			var StackAddresses []uint64
			if t.config.Output.StackAddresses {
				StackAddresses, _ = t.getStackAddresses(rawEvent.Ctx.StackID)
			}

			// Currently, the timestamp received from the bpf code is of the monotonic clock.
			// Todo: The monotonic clock doesn't take into account system sleep time.
			// Starting from kernel 5.7, we can get the timestamp relative to the system boot time instead which is preferable.
			if t.config.Output.RelativeTime {
				// To get the monotonic time since tracee was started, we have to substract the start time from the timestamp.
				rawEvent.Ctx.Ts -= t.startTime
			} else {
				// To get the current ("wall") time, we add the boot time into it.
				rawEvent.Ctx.Ts += t.bootTime
			}

			evt, err := newEvent(rawEvent.Ctx, rawEvent.ArgMetas, rawEvent.Args, StackAddresses)
			if err != nil {
				errc <- err
				continue
			}

			select {
			case <-done:
				return
			case t.config.ChanEvents <- evt:
				t.stats.eventCounter.Increment()
			}
		}
	}()
	return errc, nil
}

// WaitForPipeline waits for results from all error channels.
func (t *Tracee) WaitForPipeline(errs ...<-chan error) error {
	errc := MergeErrors(errs...)
	for err := range errc {
		t.handleError(err)
	}
	return nil
}

func (t *Tracee) handleError(err error) {
	t.stats.errorCounter.Increment()
	t.config.ChanErrors <- err
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

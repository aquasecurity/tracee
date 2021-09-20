package tracee

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
	"unsafe"

	"github.com/aquasecurity/tracee/tracee-ebpf/external"
)

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

func (t *Tracee) processEvents(done <-chan struct{}) error {
		for dataRaw := range t.eventsChannel {
			dataBuff := bytes.NewBuffer(dataRaw)
			var ctx context
			err := binary.Read(dataBuff, binary.LittleEndian, &ctx)
			if err != nil {
				t.handleError(err)
				continue
			}

			rawEvent := RawEvent{
				Ctx:      ctx,
				Args:     make(map[string]interface{}, ctx.Argnum),
				ArgMetas: make([]external.ArgMeta, ctx.Argnum),
			}

			params := EventsIDToParams[ctx.EventID]
			if params == nil {
				t.handleError(fmt.Errorf("failed to get parameters of event %d", ctx.EventID))
				continue
			}

			for i := 0; i < int(ctx.Argnum); i++ {
				argMeta, argVal, err := readArgFromBuff(dataBuff, params)
				if err != nil {
					t.handleError(fmt.Errorf("failed to read argument %d of event %d: %v", i, ctx.EventID, err))
					continue
				}

				rawEvent.Args[argMeta.Name] = argVal
				rawEvent.ArgMetas[i] = argMeta
			}

			if !t.shouldProcessEvent(rawEvent) {
				continue
			}
			err = t.processEvent(&rawEvent.Ctx, rawEvent.Args)
			if err != nil {
				t.handleError(err)
				continue
			}

			// Only emit events requested by the user
			if !t.eventsToTrace[rawEvent.Ctx.EventID] {
				continue
			}
			err = t.prepareArgs(&rawEvent.Ctx, rawEvent.Args)
			if err != nil {
				t.handleError(err)
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

			evt := external.Event{
				Timestamp:           int(rawEvent.Ctx.Ts),
				ProcessID:           int(rawEvent.Ctx.Pid),
				ThreadID:            int(rawEvent.Ctx.Tid),
				ParentProcessID:     int(rawEvent.Ctx.Ppid),
				HostProcessID:       int(rawEvent.Ctx.HostPid),
				HostThreadID:        int(rawEvent.Ctx.HostTid),
				HostParentProcessID: int(rawEvent.Ctx.HostPpid),
				UserID:              int(rawEvent.Ctx.Uid),
				MountNS:             int(rawEvent.Ctx.MntID),
				PIDNS:               int(rawEvent.Ctx.PidID),
				ProcessName:         string(bytes.TrimRight(rawEvent.Ctx.Comm[:], "\x00")),
				HostName:            string(bytes.TrimRight(rawEvent.Ctx.UtsName[:], "\x00")),
				ContainerID:         string(bytes.TrimRight(rawEvent.Ctx.ContID[:], "\x00")),
				EventID:             int(rawEvent.Ctx.EventID),
				EventName:           EventsIDToEvent[int32(rawEvent.Ctx.EventID)].Name,
				ArgsNum:             int(rawEvent.Ctx.Argnum),
				ReturnValue:         int(rawEvent.Ctx.Retval),
				Args:                make([]external.Argument, 0, len(rawEvent.Args)),
				StackAddresses:      StackAddresses,
			}
			for _, meta := range rawEvent.ArgMetas {
				evt.Args = append(evt.Args, external.Argument{
					ArgMeta: meta,
					Value:   rawEvent.Args[meta.Name],
				})
			}

			select {
			case <-done:
				return nil
			case t.config.ChanEvents <- evt:
				t.stats.eventCounter.Increment()
			}
		}
		return nil
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

func (t *Tracee) handleError(err error) {
	t.stats.errorCounter.Increment()
	t.config.ChanErrors <- err
}

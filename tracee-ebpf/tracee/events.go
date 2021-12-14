package tracee

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
	"unsafe"

	"github.com/aquasecurity/tracee/pkg/external"
)

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

func (t *Tracee) processEvents(done <-chan struct{}) error {
	for dataRaw := range t.eventsChannel {
		dataBuff := bytes.NewBuffer(dataRaw)
		var ctx context
		err := binary.Read(dataBuff, binary.LittleEndian, &ctx)
		if err != nil {
			t.handleError(err)
			continue
		}

		args := make(map[string]interface{}, ctx.Argnum)
		argMetas := make([]external.ArgMeta, ctx.Argnum)

		params := EventsIDToParams[ctx.EventID]
		if params == nil {
			t.handleError(fmt.Errorf("failed to get parameters of event %d", ctx.EventID))
			continue
		}

		for i := 0; i < int(ctx.Argnum); i++ {
			argMeta, argVal, err := readArgFromBuff(dataBuff, params)
			if err != nil {
				t.handleError(fmt.Errorf("failed to read argument %d of event %s: %v", i, EventsIDToEvent[ctx.EventID].Name, err))
				continue
			}

			args[argMeta.Name] = argVal
			argMetas[i] = argMeta
		}

		if !t.shouldProcessEvent(&ctx, args) {
			continue
		}
		err = t.processEvent(&ctx, args, &argMetas)
		if err != nil {
			t.handleError(err)
			continue
		}

		if !t.containers.CgroupExists(ctx.CgroupID) {
			// Handle false container negatives (we should have identified this container id, but we didn't)
			// This situation can happen as a race condition when updating the cgroup map.
			// In that case, we can try to look for it in the cgroupfs and update the map if found.
			t.containers.CgroupLookupUpdate(ctx.CgroupID)
		}
		containerId := t.containers.GetCgroupInfo(ctx.CgroupID).ContainerId
		if (t.config.Filter.ContFilter.Enabled || t.config.Filter.NewContFilter.Enabled) && containerId == "" {
			// Don't trace false container positives -
			// a container filter is set by the user, but this event wasn't originated in a container.
			// Although kernel filters shouldn't submit such events, we do this check to be on the safe side.
			// For example, it might be that a new cgroup was created, and not by a container runtime,
			// while we still didn't processed the cgroup_mkdir event and removed the cgroupid from the bpf container map.
			continue
		}

		// Only emit events requested by the user
		if !t.eventsToTrace[ctx.EventID] {
			continue
		}

		if t.config.Output.ParseArguments {
			err = t.parseArgs(&ctx, args, &argMetas)
			if err != nil {
				t.handleError(err)
				continue
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
			ContainerID:         containerId,
			EventID:             int(ctx.EventID),
			EventName:           EventsIDToEvent[int32(ctx.EventID)].Name,
			ArgsNum:             int(ctx.Argnum),
			ReturnValue:         int(ctx.Retval),
			Args:                make([]external.Argument, 0, len(args)),
			StackAddresses:      StackAddresses,
		}
		for _, meta := range argMetas {
			evt.Args = append(evt.Args, external.Argument{
				ArgMeta: meta,
				Value:   args[meta.Name],
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

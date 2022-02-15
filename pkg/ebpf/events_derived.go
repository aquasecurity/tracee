package ebpf

import (
	"fmt"

	"github.com/aquasecurity/tracee/types/trace"
)

type deriveFn func(EventDefinition) error

func (t *Tracee) deriveEvent(event trace.Event) []trace.Event {
	var deriveFns map[int32]deriveFn
	var derivatives []trace.Event

	eventID := int32(event.EventID)
	switch eventID {
	case CgroupMkdirEventID:
		containerCreateFn := func(def EventDefinition) error {
			cgroupId, err := getEventArgUint64Val(&event, "cgroup_id")
			if err != nil {
				return err
			}

			if info := t.containers.GetCgroupInfo(cgroupId); info.ContainerId != "" {
				de := event
				de.EventID = int(ContainerCreateEventID)
				de.EventName = "container_create"
				de.ReturnValue = 0
				de.StackAddresses = make([]uint64, 1)
				de.Args = []trace.Argument{
					{ArgMeta: def.Params[0], Value: info.Runtime},
					{ArgMeta: def.Params[1], Value: info.ContainerId},
					{ArgMeta: def.Params[2], Value: info.Ctime.UnixNano()},
				}
				de.ArgsNum = 3

				derivatives = append(derivatives, de)
			}

			return nil
		}
		deriveFns = map[int32]deriveFn{
			ContainerCreateEventID: containerCreateFn,
		}
	case CgroupRmdirEventID:
		containerRemoveFn := func(def EventDefinition) error {
			cgroupId, err := getEventArgUint64Val(&event, "cgroup_id")
			if err != nil {
				return err
			}

			if info := t.containers.GetCgroupInfo(cgroupId); info.ContainerId != "" {
				de := event
				de.EventID = int(ContainerRemoveEventID)
				de.EventName = "container_remove"
				de.ReturnValue = 0
				de.StackAddresses = make([]uint64, 1)
				de.Args = []trace.Argument{
					{ArgMeta: def.Params[0], Value: info.Runtime},
					{ArgMeta: def.Params[1], Value: info.ContainerId},
				}
				de.ArgsNum = 2

				derivatives = append(derivatives, de)
			}

			return nil
		}
		deriveFns = map[int32]deriveFn{
			ContainerRemoveEventID: containerRemoveFn,
		}
	}

	for id, deriveFn := range deriveFns {
		// Don't derive events which were not requested by the user
		if !t.eventsToTrace[id] {
			continue
		}

		def, ok := EventsDefinitions[id]
		if !ok {
			t.handleError(fmt.Errorf("failed to get configuration of event %d", id))
			continue
		}

		if err := deriveFn(def); err != nil {
			t.handleError(fmt.Errorf("failed to derive event %d: %v", id, err))
		}
	}

	return derivatives
}

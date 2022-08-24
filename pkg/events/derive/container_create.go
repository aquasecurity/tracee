package derive

import (
	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/types/trace"
)

// ContainerCreate receives a containers as a closure argument to track it's containers.
// If it receives a cgroup_mkdir event, it can derive a container_create event from it.
func ContainerCreate(containers *containers.Containers) deriveFunction {
	return deriveSingleEvent(events.ContainerCreate, deriveContainerCreateArgs(containers))
}

func deriveContainerCreateArgs(containers *containers.Containers) func(event trace.Event) ([]interface{}, error) {
	return func(event trace.Event) ([]interface{}, error) {
		cgroupId, err := parse.ArgUint64Val(&event, "cgroup_id")
		if err != nil {
			return nil, err
		}
		if info := containers.GetCgroupInfo(cgroupId); info.Container.ContainerId != "" {
			args := []interface{}{
				info.Runtime.String(),
				info.Container.ContainerId,
				info.Ctime.UnixNano(),
				info.Container.Image,
				info.Container.Name,
				info.Container.Pod.Name,
				info.Container.Pod.Namespace,
				info.Container.Pod.UID,
			}
			return args, nil
		}
		return nil, nil
	}
}

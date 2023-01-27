package derive

import (
	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/types/trace"
)

// ContainerRemove receives a containers.Containers object as a closure argument to track it's containers.
// If it receives a cgroup_rmdir event, it can derive a container_remove event from it.
func ContainerRemove(containers *containers.Containers) DeriveFunction {
	return deriveSingleEvent(events.ContainerRemove, deriveContainerRemoveArgs(containers))
}

func deriveContainerRemoveArgs(containers *containers.Containers) deriveArgsFunction {
	return func(event trace.Event) ([]interface{}, error) {
		// if cgroup_id is from non default hid (v1 case), the cgroup info query will fail, so we skip
		if check, err := isCgroupEventInHid(&event, containers); !check {
			return nil, err
		}
		cgroupId, err := parse.ArgVal[uint64](&event, "cgroup_id")
		if err != nil {
			return nil, err
		}
		if info := containers.GetCgroupInfo(cgroupId); info.Container.ContainerId != "" {
			return []interface{}{info.Runtime.String(), info.Container.ContainerId}, nil
		}
		return nil, nil
	}
}

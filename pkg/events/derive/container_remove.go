package derive

import (
	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/pkg/datastores/container"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/types/trace"
)

// ContainerRemove receives a container.Manager object as a closure argument to track its containers.
// If it receives a cgroup_rmdir event, it can derive a container_remove event from it.
func ContainerRemove(cts *container.Manager) DeriveFunction {
	return deriveSingleEvent(events.ContainerRemove, deriveContainerRemoveArgs(cts))
}

func deriveContainerRemoveArgs(cts *container.Manager) deriveArgsFunction {
	return func(event *trace.Event) ([]interface{}, error) {
		// if cgroup_id is from non default hid (v1 case), the cgroup info query will fail, so we skip
		if check, err := isCgroupEventInHid(event, cts); !check {
			return nil, errfmt.WrapError(err)
		}
		cgroupId, err := parse.ArgVal[uint64](event.Args, "cgroup_id")
		if err != nil {
			return nil, errfmt.WrapError(err)
		}
		if _, container := cts.GetCgroupInfo(cgroupId); container.ContainerId != "" {
			return []interface{}{container.Runtime.String(), container.ContainerId}, nil
		}
		return nil, nil
	}
}

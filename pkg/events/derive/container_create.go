package derive

import (
	"github.com/aquasecurity/tracee/pkg/cgroup"
	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/pkg/events/pipeline"
	"github.com/aquasecurity/tracee/pkg/logger"
)

// ContainerCreate receives a containers as a closure argument to track it's containers.
// If it receives a cgroup_mkdir event, it can derive a container_create event from it.
func ContainerCreate(cts *containers.Manager) DeriveFunction {
	return deriveSingleEvent(events.ContainerCreate, deriveContainerCreateArgs(cts))
}

func deriveContainerCreateArgs(cts *containers.Manager) func(event pipeline.Event) ([]interface{}, error) {
	return func(event pipeline.Event) ([]interface{}, error) {
		// if cgroup_id is from non default hid (v1 case), the cgroup info query will fail, so we skip
		if check, err := isCgroupEventInHid(&event, cts); !check {
			return nil, errfmt.WrapError(err)
		}
		cgroupId, err := parse.ArgVal[uint64](event.Args, "cgroup_id")
		if err != nil {
			return nil, errfmt.WrapError(err)
		}
		if info, container := cts.GetCgroupInfo(cgroupId); info.ContainerRoot {
			logger.Debugw("derive container_create from cgroup", "cgroup_id", cgroupId, "container_id", container.ContainerId)
			args := []interface{}{
				container.Runtime.String(),
				container.ContainerId,
				container.CreatedAt.UnixNano(),
				container.Image,
				container.ImageDigest,
				container.Name,
				container.Pod.Name,
				container.Pod.Namespace,
				container.Pod.UID,
				container.Pod.Sandbox,
			}
			return args, nil
		}
		return nil, nil
	}
}

// isCgroupEventInHid checks if cgroup event is relevant for deriving container event in its hierarchy id.
// in tracee we only care about containers inside the cpuset controller, as such other hierarchy ids will lead
// to a failed query.
func isCgroupEventInHid(event *pipeline.Event, cts *containers.Manager) (bool, error) {
	if cts.GetCgroupVersion() == cgroup.CgroupVersion2 {
		return true, nil
	}
	hierarchyID, err := parse.ArgVal[uint32](event.Args, "hierarchy_id")
	if err != nil {
		return false, errfmt.WrapError(err)
	}
	return cts.GetDefaultCgroupHierarchyID() == int(hierarchyID), nil
}

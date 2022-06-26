package filters

import (
	"fmt"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/tracee/pkg/containers"
)

type ContainersFilter struct {
	*StringFilter
}

func (f *ContainersFilter) InitBpf(module *bpf.Module, mapName string, containers *containers.Containers) error {
	filterMap, err := module.GetMap(mapName)
	if err != nil {
		return err
	}

	for equalFilter := range f.equals {
		cgroupIDs := containers.FindContainerCgroupID32LSB(equalFilter)
		if cgroupIDs == nil {
			return fmt.Errorf("container id not found: %s", equalFilter)
		}
		if len(cgroupIDs) > 1 {
			return fmt.Errorf("container id is ambiguous: %s", equalFilter)
		}
		if err = filterMap.Update(unsafe.Pointer(&cgroupIDs[0]), unsafe.Pointer(&bpfFilterEqual)); err != nil {
			return err
		}
	}
	for notEqualFilter := range f.notEquals {
		cgroupIDs := containers.FindContainerCgroupID32LSB(notEqualFilter)
		if cgroupIDs == nil {
			return fmt.Errorf("container id not found: %s", notEqualFilter)
		}
		if len(cgroupIDs) > 1 {
			return fmt.Errorf("container id is ambiguous: %s", notEqualFilter)
		}
		if err = filterMap.Update(unsafe.Pointer(&cgroupIDs[0]), unsafe.Pointer(&bpfFilterNotEqual)); err != nil {
			return err
		}
	}

	return nil
}

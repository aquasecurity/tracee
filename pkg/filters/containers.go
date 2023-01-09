package filters

import (
	"fmt"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/containers"
)

type ContainerFilter struct {
	*BPFStringFilter
}

func NewContainerFilter(mapName string) *ContainerFilter {
	return &ContainerFilter{
		BPFStringFilter: NewBPFStringFilter(mapName),
	}
}

func (f *ContainerFilter) InitBPF(bpfModule *bpf.Module, containers *containers.Containers) error {
	if !f.Enabled() {
		return nil
	}

	bpfFilterEqual := uint32(filterEqual) // const need local var for bpfMap.Update()
	bpfFilterNotEqual := uint32(filterNotEqual)

	filterMap, err := bpfModule.GetMap(f.mapName)
	if err != nil {
		return err
	}

	for _, equalFilter := range f.Equal() {
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

	for _, notEqualFilter := range f.NotEqual() {
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

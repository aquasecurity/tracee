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

func (filter *ContainerFilter) InitBPF(bpfModule *bpf.Module, conts *containers.Containers) error {
	if !filter.Enabled() {
		return nil
	}

	filterEqualU32 := uint32(filterEqual) // const need local var for bpfMap.Update()
	filterNotEqualU32 := uint32(filterNotEqual)

	filterMap, err := bpfModule.GetMap(filter.mapName)
	if err != nil {
		return err
	}

	for i := 0; i < len(filter.Equal); i++ {
		cgroupIDs := conts.FindContainerCgroupID32LSB(filter.Equal[i])
		if cgroupIDs == nil {
			return fmt.Errorf("container id not found: %s", filter.Equal[i])
		}
		if len(cgroupIDs) > 1 {
			return fmt.Errorf("container id is ambiguous: %s", filter.Equal[i])
		}
		if err = filterMap.Update(unsafe.Pointer(&cgroupIDs[0]), unsafe.Pointer(&filterEqualU32)); err != nil {
			return err
		}
	}
	for i := 0; i < len(filter.NotEqual); i++ {
		cgroupIDs := conts.FindContainerCgroupID32LSB(filter.NotEqual[i])
		if cgroupIDs == nil {
			return fmt.Errorf("container id not found: %s", filter.NotEqual[i])
		}
		if len(cgroupIDs) > 1 {
			return fmt.Errorf("container id is ambiguous: %s", filter.Equal[i])
		}
		if err = filterMap.Update(unsafe.Pointer(&cgroupIDs[0]), unsafe.Pointer(&filterNotEqualU32)); err != nil {
			return err
		}
	}

	return nil
}

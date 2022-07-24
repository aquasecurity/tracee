package filters

import (
	"fmt"
	"strconv"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/types/protocol"
)

type ContainerFilter struct {
	IdFilter   *BPFStringFilter
	ModeFilter *BoolFilter
	mapName    string
}

func NewContainerFilter(mapName string, filters ...protocol.Filter) (*ContainerFilter, error) {
	stringFilter, _ := NewBPFStringFilter(mapName)
	boolFilter, _ := NewBoolFilter()

	filter := &ContainerFilter{
		IdFilter:   stringFilter,
		ModeFilter: boolFilter,
		mapName:    mapName,
	}

	for _, f := range filters {
		err := filter.parse(f)
		if err != nil {
			return filter, err
		}
	}

	return filter, nil
}

func (f *ContainerFilter) parse(filter protocol.Filter) error {
	for _, val := range filter.Value {
		val := fmt.Sprintf("%v", val)
		boolVal, err := strconv.ParseBool(val)

		if err == nil { // if value is bool, put into the container filter mode
			err := f.addModeFilter(boolVal, Operator(filter.Operator))
			if err != nil {
				return err
			}
		} else { // otherwise put in id filter
			f.addIdFilter(val, Operator(filter.Operator))
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (f *ContainerFilter) addModeFilter(val bool, operator Operator) error {
	err := f.ModeFilter.add(val, operator)
	if err != nil {
		return err
	}
	f.ModeFilter.Enable()
	return nil
}

func (f *ContainerFilter) addIdFilter(val string, operator Operator) error {
	err := f.IdFilter.add(val, operator)
	if err != nil {
		return err
	}
	f.IdFilter.Enable()
	return nil
}

func (f *ContainerFilter) InitBPF(bpfModule *bpf.Module, containers *containers.Containers) error {
	if !f.IdFilter.Enabled() {
		return nil
	}

	bpfFilterEqual := uint32(filterEqual) // const need local var for bpfMap.Update()
	bpfFilterNotEqual := uint32(filterNotEqual)

	filterMap, err := bpfModule.GetMap(f.mapName)
	if err != nil {
		return err
	}

	for equalFilter := range f.IdFilter.equal {
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

	for notEqualFilter := range f.IdFilter.notEqual {
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

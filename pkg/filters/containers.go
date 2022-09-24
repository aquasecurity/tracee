package filters

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/tracee/pkg/containers"
)

type ContIDFilter struct {
	Equal    []string
	NotEqual []string
	Enabled  bool
}

func (filter *ContIDFilter) Parse(operatorAndValues string) error {
	filter.Enabled = true

	strFilter := &StringFilter{
		Equal:    []string{},
		NotEqual: []string{},
	}

	// Treat operatorAndValues as a string filter to avoid code duplication
	err := strFilter.Parse(operatorAndValues)
	if err != nil {
		return err
	}

	filter.Equal = strFilter.Equal
	filter.NotEqual = strFilter.NotEqual

	return nil
}

func (filter *ContIDFilter) InitBPF(bpfModule *bpf.Module, conts *containers.Containers, filterMapName string, filterScopeID uint32) error {
	if !filter.Enabled {
		return nil
	}

	filterMap, err := bpfModule.GetMap(filterMapName)
	if err != nil {
		return err
	}
	filterVal := make([]byte, 8)

	for i := 0; i < len(filter.Equal); i++ {
		cgroupIDs := conts.FindContainerCgroupID32LSB(filter.Equal[i])
		if cgroupIDs == nil {
			return fmt.Errorf("container id not found: %s", filter.Equal[i])
		}
		if len(cgroupIDs) > 1 {
			return fmt.Errorf("container id is ambiguous: %s", filter.Equal[i])
		}

		var validBits uint32
		curVal, err := filterMap.GetValue(unsafe.Pointer(&cgroupIDs[0]))
		if err == nil {
			validBits = binary.LittleEndian.Uint32(curVal[4:8])
		}
		binary.LittleEndian.PutUint32(filterVal[0:4], uint32(filterEqual))          // bitmask
		binary.LittleEndian.PutUint32(filterVal[4:8], validBits|(1<<filterScopeID)) // valid_bits
		if err = filterMap.Update(unsafe.Pointer(&cgroupIDs[0]), unsafe.Pointer(&filterVal[0])); err != nil {
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

		var validBits uint32
		curVal, err := filterMap.GetValue(unsafe.Pointer(&cgroupIDs[0]))
		if err == nil {
			validBits = binary.LittleEndian.Uint32(curVal[4:8])
		}
		binary.LittleEndian.PutUint32(filterVal[0:4], uint32(filterNotEqual))       // bitmask
		binary.LittleEndian.PutUint32(filterVal[4:8], validBits|(1<<filterScopeID)) // valid_bits
		if err = filterMap.Update(unsafe.Pointer(&cgroupIDs[0]), unsafe.Pointer(&filterVal[0])); err != nil {
			return err
		}
	}

	return nil
}

func (filter *ContIDFilter) FilterOut() bool {
	if len(filter.Equal) > 0 && len(filter.NotEqual) == 0 {
		return false
	} else {
		return true
	}
}

package filters

import (
	"encoding/binary"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/utils"
)

type ContainerFilter struct {
	*BPFStringFilter
}

func NewContainerFilter(mapName string) *ContainerFilter {
	return &ContainerFilter{
		BPFStringFilter: NewBPFStringFilter(mapName),
	}
}

func (f *ContainerFilter) UpdateBPF(bpfModule *bpf.Module, containers *containers.Containers, policyID uint) error {
	if !f.Enabled() {
		return nil
	}

	filterMap, err := bpfModule.GetMap(f.mapName)
	if err != nil {
		return errfmt.WrapError(err)
	}

	filterVal := make([]byte, 16)

	// first initialize notEqual values since equality should take precedence
	for _, notEqualFilter := range f.NotEqual() {
		cgroupIDs := containers.FindContainerCgroupID32LSB(notEqualFilter)
		if cgroupIDs == nil {
			return errfmt.Errorf("container id not found: %s", notEqualFilter)
		}
		if len(cgroupIDs) > 1 {
			return errfmt.Errorf("container id is ambiguous: %s", notEqualFilter)
		}

		var equalInPolicies, equalitySetInPolicies uint64
		curVal, err := filterMap.GetValue(unsafe.Pointer(&cgroupIDs[0]))
		if err == nil {
			equalInPolicies = binary.LittleEndian.Uint64(curVal[0:8])
			equalitySetInPolicies = binary.LittleEndian.Uint64(curVal[8:16])
		}

		// filterNotEqual == 0, so clear n bitmask bit
		utils.ClearBit(&equalInPolicies, policyID)
		utils.SetBit(&equalitySetInPolicies, policyID)

		binary.LittleEndian.PutUint64(filterVal[0:8], equalInPolicies)
		binary.LittleEndian.PutUint64(filterVal[8:16], equalitySetInPolicies)
		if err = filterMap.Update(unsafe.Pointer(&cgroupIDs[0]), unsafe.Pointer(&filterVal[0])); err != nil {
			return errfmt.WrapError(err)
		}
	}

	// now - setup equality filters
	for _, equalFilter := range f.Equal() {
		cgroupIDs := containers.FindContainerCgroupID32LSB(equalFilter)
		if cgroupIDs == nil {
			return errfmt.Errorf("container id not found: %s", equalFilter)
		}
		if len(cgroupIDs) > 1 {
			return errfmt.Errorf("container id is ambiguous: %s", equalFilter)
		}

		var equalInPolicies, equalitySetInPolicies uint64
		curVal, err := filterMap.GetValue(unsafe.Pointer(&cgroupIDs[0]))
		if err == nil {
			equalInPolicies = binary.LittleEndian.Uint64(curVal[0:8])
			equalitySetInPolicies = binary.LittleEndian.Uint64(curVal[8:16])
		}

		// filterEqual == 1, so set n bitmask bit
		utils.SetBit(&equalInPolicies, policyID)
		utils.SetBit(&equalitySetInPolicies, policyID)

		binary.LittleEndian.PutUint64(filterVal[0:8], equalInPolicies)
		binary.LittleEndian.PutUint64(filterVal[8:16], equalitySetInPolicies)
		if err = filterMap.Update(unsafe.Pointer(&cgroupIDs[0]), unsafe.Pointer(&filterVal[0])); err != nil {
			return errfmt.WrapError(err)
		}
	}

	return nil
}

package filters

import (
	"github.com/aquasecurity/tracee/tracee-ebpf/engine/consts"
)

type Filter struct {
	EventsToTrace []int32
	UIDFilter     *UintFilter
	PIDFilter     *UintFilter
	NewPidFilter  *BoolFilter
	MntNSFilter   *UintFilter
	PidNSFilter   *UintFilter
	UTSFilter     *StringFilter
	CommFilter    *StringFilter
	ContFilter    *BoolFilter
	NewContFilter *BoolFilter
	RetFilter     *RetFilter
	ArgFilter     *ArgFilter
	Follow        bool
}

type UintFilter struct {
	Equal    []uint64
	NotEqual []uint64
	Greater  uint64
	Less     uint64
	Is32Bit  bool
	Enabled  bool
}

type IntFilter struct {
	Equal    []int64
	NotEqual []int64
	Greater  int64
	Less     int64
	Is32Bit  bool
	Enabled  bool
}

type StringFilter struct {
	Equal    []string
	NotEqual []string
	Enabled  bool
}

type BoolFilter struct {
	Value   bool
	Enabled bool
}

type RetFilter struct {
	Filters map[int32]IntFilter
	Enabled bool
}

type ArgFilter struct {
	Filters map[int32]map[string]ArgFilterVal // key to the first map is event id, and to the second map the argument name
	Enabled bool
}

type ArgFilterVal struct {
	ArgTag   consts.ArgTag
	Equal    []string
	NotEqual []string
}

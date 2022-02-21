package ebpf

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"strconv"
	"strings"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/tracee/pkg/containers"
)

const (
	filterNotEqual uint32 = iota
	filterEqual
)

const (
	uidLess uint32 = iota
	uidGreater
	pidLess
	pidGreater
	mntNsLess
	mntNsGreater
	pidNsLess
	pidNsGreater
)

// Set default inequality values
// val<0 and val>math.MaxUint64 should never be used by the user as they give an empty set
const (
	LessNotSetUint    uint64 = 0
	GreaterNotSetUint uint64 = math.MaxUint64
	LessNotSetInt     int64  = math.MinInt64
	GreaterNotSetInt  int64  = math.MaxInt64
)

type Filter struct {
	EventsToTrace     []int32
	UIDFilter         *UintFilter
	PIDFilter         *UintFilter
	NewPidFilter      *BoolFilter
	MntNSFilter       *UintFilter
	PidNSFilter       *UintFilter
	UTSFilter         *StringFilter
	CommFilter        *StringFilter
	ContFilter        *BoolFilter
	NewContFilter     *BoolFilter
	ContIDFilter      *ContIDFilter
	RetFilter         *RetFilter
	ArgFilter         *ArgFilter
	ProcessTreeFilter *ProcessTreeFilter
	Follow            bool
}

type UintFilter struct {
	Equal    []uint64
	NotEqual []uint64
	Greater  uint64
	Less     uint64
	Is32Bit  bool
	Enabled  bool
}

func (filter *UintFilter) Parse(operatorAndValues string) error {
	filter.Enabled = true
	if len(operatorAndValues) < 2 {
		return fmt.Errorf("invalid operator and/or values given to filter: %s", operatorAndValues)
	}
	valuesString := string(operatorAndValues[1:])
	operatorString := string(operatorAndValues[0])

	if operatorString == "!" {
		if len(operatorAndValues) < 3 {
			return fmt.Errorf("invalid operator and/or values given to filter: %s", operatorAndValues)
		}
		operatorString = operatorAndValues[0:2]
		valuesString = operatorAndValues[2:]
	}

	values := strings.Split(valuesString, ",")

	for i := range values {
		val, err := strconv.ParseUint(values[i], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid filter value: %s", values[i])
		}
		if filter.Is32Bit && (val > math.MaxUint32) {
			return fmt.Errorf("filter value is too big: %s", values[i])
		}
		switch operatorString {
		case "=":
			filter.Equal = append(filter.Equal, val)
		case "!=":
			filter.NotEqual = append(filter.NotEqual, val)
		case ">":
			if (filter.Greater == GreaterNotSetUint) || (val > filter.Greater) {
				filter.Greater = val
			}
		case "<":
			if (filter.Less == LessNotSetUint) || (val < filter.Less) {
				filter.Less = val
			}
		default:
			return fmt.Errorf("invalid filter operator: %s", operatorString)
		}
	}

	return nil
}

func (filter *UintFilter) Set(bpfModule *bpf.Module, filterMapName string, lessIdx uint32) error {
	if !filter.Enabled {
		return nil
	}

	filterEqualU32 := uint32(filterEqual) // const need local var for bpfMap.Update()
	filterNotEqualU32 := uint32(filterNotEqual)

	// equalityFilter filters events for given maps:
	// 1. uid_filter        u32, u32
	// 2. pid_filter        u32, u32
	// 3. mnt_ns_filter     u64, u32
	// 4. pid_ns_filter     u64, u32
	equalityFilter, err := bpfModule.GetMap(filterMapName)
	if err != nil {
		return err
	}
	for i := 0; i < len(filter.Equal); i++ {
		if filter.Is32Bit {
			EqualU32 := uint32(filter.Equal[i])
			err = equalityFilter.Update(unsafe.Pointer(&EqualU32), unsafe.Pointer(&filterEqualU32))
		} else {
			err = equalityFilter.Update(unsafe.Pointer(&filter.Equal[i]), unsafe.Pointer(&filterEqualU32))
		}
		if err != nil {
			return err
		}
	}
	for i := 0; i < len(filter.NotEqual); i++ {
		if filter.Is32Bit {
			NotEqualU32 := uint32(filter.NotEqual[i])
			err = equalityFilter.Update(unsafe.Pointer(&NotEqualU32), unsafe.Pointer(&filterNotEqualU32))
		} else {
			err = equalityFilter.Update(unsafe.Pointer(&filter.NotEqual[i]), unsafe.Pointer(&filterNotEqualU32))
		}
		if err != nil {
			return err
		}
	}

	filterLess := filter.Less
	filterGreater := filter.Greater

	// inequalityFilter filters events by some uint field either by < or >
	inequalityFilter, err := bpfModule.GetMap("inequality_filter") // u32, u64
	if err != nil {
		return err
	}
	if err = inequalityFilter.Update(unsafe.Pointer(&lessIdx), unsafe.Pointer(&filterLess)); err != nil {
		return err
	}
	lessIdxPlus := uint32(lessIdx + 1)
	if err = inequalityFilter.Update(unsafe.Pointer(&lessIdxPlus), unsafe.Pointer(&filterGreater)); err != nil {
		return err
	}

	return nil
}

func (filter *UintFilter) FilterOut() bool {
	if len(filter.Equal) > 0 && len(filter.NotEqual) == 0 && filter.Greater == GreaterNotSetUint && filter.Less == LessNotSetUint {
		return false
	} else {
		return true
	}
}

type IntFilter struct {
	Equal    []int64
	NotEqual []int64
	Greater  int64
	Less     int64
	Is32Bit  bool
	Enabled  bool
}

func (filter *IntFilter) Parse(operatorAndValues string) error {
	filter.Enabled = true
	if len(operatorAndValues) < 2 {
		return fmt.Errorf("invalid operator and/or values given to filter: %s", operatorAndValues)
	}
	valuesString := string(operatorAndValues[1:])
	operatorString := string(operatorAndValues[0])

	if operatorString == "!" {
		if len(operatorAndValues) < 3 {
			return fmt.Errorf("invalid operator and/or values given to filter: %s", operatorAndValues)
		}
		operatorString = operatorAndValues[0:2]
		valuesString = operatorAndValues[2:]
	}

	values := strings.Split(valuesString, ",")

	for i := range values {
		val, err := strconv.ParseInt(values[i], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid filter value: %s", values[i])
		}
		if filter.Is32Bit && (val > math.MaxInt32) {
			return fmt.Errorf("filter value is too big: %s", values[i])
		}
		switch operatorString {
		case "=":
			filter.Equal = append(filter.Equal, val)
		case "!=":
			filter.NotEqual = append(filter.NotEqual, val)
		case ">":
			if (filter.Greater == GreaterNotSetInt) || (val > filter.Greater) {
				filter.Greater = val
			}
		case "<":
			if (filter.Less == LessNotSetInt) || (val < filter.Less) {
				filter.Less = val
			}
		default:
			return fmt.Errorf("invalid filter operator: %s", operatorString)
		}
	}

	return nil
}

type StringFilter struct {
	Equal    []string
	NotEqual []string
	Enabled  bool
}

func (filter *StringFilter) Parse(operatorAndValues string) error {
	filter.Enabled = true
	if len(operatorAndValues) < 2 {
		return fmt.Errorf("invalid operator and/or values given to filter: %s", operatorAndValues)
	}
	valuesString := string(operatorAndValues[1:])
	operatorString := string(operatorAndValues[0])

	if operatorString == "!" {
		if len(operatorAndValues) < 3 {
			return fmt.Errorf("invalid operator and/or values given to filter: %s", operatorAndValues)
		}
		operatorString = operatorAndValues[0:2]
		valuesString = operatorAndValues[2:]
	}

	values := strings.Split(valuesString, ",")

	for i := range values {
		switch operatorString {
		case "=":
			filter.Equal = append(filter.Equal, values[i])
		case "!=":
			filter.NotEqual = append(filter.NotEqual, values[i])
		default:
			return fmt.Errorf("invalid filter operator: %s", operatorString)
		}
	}

	return nil
}

func (filter *StringFilter) Set(bpfModule *bpf.Module, filterMapName string) error {
	if !filter.Enabled {
		return nil
	}

	filterEqualU32 := uint32(filterEqual) // const need local var for bpfMap.Update()
	filterNotEqualU32 := uint32(filterNotEqual)

	// 1. uts_ns_filter     string[MAX_STR_FILTER_SIZE], u32    // filter events by uts namespace name
	// 2. comm_filter       string[MAX_STR_FILTER_SIZE], u32    // filter events by command name
	filterMap, err := bpfModule.GetMap(filterMapName)
	if err != nil {
		return err
	}
	for i := 0; i < len(filter.Equal); i++ {
		filterEqualBytes := []byte(filter.Equal[i])
		if err = filterMap.Update(unsafe.Pointer(&filterEqualBytes[0]), unsafe.Pointer(&filterEqualU32)); err != nil {
			return err
		}
	}
	for i := 0; i < len(filter.NotEqual); i++ {
		filterNotEqualBytes := []byte(filter.NotEqual[i])
		if err = filterMap.Update(unsafe.Pointer(&filterNotEqualBytes[0]), unsafe.Pointer(&filterNotEqualU32)); err != nil {
			return err
		}
	}

	return nil
}

func (filter *StringFilter) FilterOut() bool {
	if len(filter.Equal) > 0 && len(filter.NotEqual) == 0 {
		return false
	} else {
		return true
	}
}

type BoolFilter struct {
	Value   bool
	Enabled bool
}

func (filter *BoolFilter) Parse(value string) error {
	filter.Enabled = true
	filter.Value = false
	if value[0] != '!' {
		filter.Value = true
	}

	return nil
}

func (filter *BoolFilter) FilterOut() bool {
	if filter.Value {
		return false
	} else {
		return true
	}
}

type RetFilter struct {
	Filters map[int32]IntFilter
	Enabled bool
}

func (filter *RetFilter) Parse(filterName string, operatorAndValues string, eventsNameToID map[string]int32) error {
	filter.Enabled = true
	// Ret filter has the following format: "event.ret=val"
	// filterName have the format event.retval, and operatorAndValues have the format "=val"
	splitFilter := strings.Split(filterName, ".")
	if len(splitFilter) != 2 || splitFilter[1] != "retval" {
		return fmt.Errorf("invalid retval filter format %s%s", filterName, operatorAndValues)
	}
	eventName := splitFilter[0]

	id, ok := eventsNameToID[eventName]
	if !ok {
		return fmt.Errorf("invalid retval filter event name: %s", eventName)
	}

	if _, ok := filter.Filters[id]; !ok {
		filter.Filters[id] = IntFilter{
			Equal:    []int64{},
			NotEqual: []int64{},
			Less:     LessNotSetInt,
			Greater:  GreaterNotSetInt,
		}
	}

	intFilter := filter.Filters[id]

	// Treat operatorAndValues as an int filter to avoid code duplication
	err := (&intFilter).Parse(operatorAndValues)
	if err != nil {
		return err
	}

	filter.Filters[id] = intFilter

	return nil
}

type ArgFilter struct {
	Filters map[int32]map[string]ArgFilterVal // key to the first map is event id, and to the second map the argument name
	Enabled bool
}

type ArgFilterVal struct {
	Equal    []string
	NotEqual []string
}

func (filter *ArgFilter) Parse(filterName string, operatorAndValues string, eventsNameToID map[string]int32) error {
	filter.Enabled = true
	// Event argument filter has the following format: "event.argname=argval"
	// filterName have the format event.argname, and operatorAndValues have the format "=argval"
	splitFilter := strings.Split(filterName, ".")
	if len(splitFilter) != 2 {
		return fmt.Errorf("invalid argument filter format %s%s", filterName, operatorAndValues)
	}
	eventName := splitFilter[0]
	argName := splitFilter[1]

	id, ok := eventsNameToID[eventName]
	if !ok {
		return fmt.Errorf("invalid argument filter event name: %s", eventName)
	}

	eventDefinition, ok := EventsDefinitions[id]
	if !ok {
		return fmt.Errorf("invalid argument filter event name: %s", eventName)
	}
	eventParams := eventDefinition.Params

	// check if argument name exists for this event
	argFound := false
	for i := range eventParams {
		if eventParams[i].Name == argName {
			argFound = true
			break
		}
	}

	if !argFound {
		return fmt.Errorf("invalid argument filter argument name: %s", argName)
	}

	strFilter := &StringFilter{
		Equal:    []string{},
		NotEqual: []string{},
	}

	// Treat operatorAndValues as a string filter to avoid code duplication
	err := strFilter.Parse(operatorAndValues)
	if err != nil {
		return err
	}

	if _, ok := filter.Filters[id]; !ok {
		filter.Filters[id] = make(map[string]ArgFilterVal)
	}

	if _, ok := filter.Filters[id][argName]; !ok {
		filter.Filters[id][argName] = ArgFilterVal{}
	}

	val := filter.Filters[id][argName]

	val.Equal = append(val.Equal, strFilter.Equal...)
	val.NotEqual = append(val.NotEqual, strFilter.NotEqual...)

	filter.Filters[id][argName] = val

	return nil
}

type ProcessTreeFilter struct {
	PIDs    map[uint32]bool // PIDs is a map where k=pid and v represents whether it and its descendents should be traced or not
	Enabled bool
}

func (filter *ProcessTreeFilter) Parse(operatorAndValues string) error {
	filter.Enabled = true

	if len(operatorAndValues) < 2 {
		return fmt.Errorf("invalid operator and/or values given to filter: %s", operatorAndValues)
	}

	var (
		equalityOperator bool
		valuesString     string
	)

	if strings.HasPrefix(operatorAndValues, "=") {
		valuesString = operatorAndValues[1:]
		equalityOperator = true
	} else if strings.HasPrefix(operatorAndValues, "!=") {
		valuesString = operatorAndValues[2:]
		if len(valuesString) == 0 {
			return fmt.Errorf("no value passed with operator in process tree filter")
		}
		equalityOperator = false
	} else {
		return fmt.Errorf("invalid operator and/or values given to filter: %s", operatorAndValues)
	}

	values := strings.Split(valuesString, ",")
	for _, value := range values {
		pid, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return fmt.Errorf("invalid PID given to filter: %s", valuesString)
		}
		filter.PIDs[uint32(pid)] = equalityOperator
	}

	return nil
}

func (filter *ProcessTreeFilter) Set(bpfModule *bpf.Module) error {
	if !filter.Enabled {
		return nil
	}

	processTreeBPFMap, err := bpfModule.GetMap("process_tree_map")
	if err != nil {
		return fmt.Errorf("could not find bpf process_tree_map: %v", err)
	}

	procDir, err := os.Open("/proc")
	if err != nil {
		return fmt.Errorf("could not open proc dir: %v", err)
	}
	defer procDir.Close()

	entries, err := procDir.Readdirnames(-1)
	if err != nil {
		return fmt.Errorf("could not read proc dir: %v", err)
	}

	// Iterate over each pid
	for _, entry := range entries {
		pid, err := strconv.ParseUint(entry, 10, 32)
		if err != nil {
			continue
		}
		var fn func(uint32)
		fn = func(curPid uint32) {
			stat, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/stat", curPid))
			if err != nil {
				return
			}
			// see https://man7.org/linux/man-pages/man5/proc.5.html for how to read /proc/pid/stat
			splitStat := bytes.SplitN(stat, []byte{' '}, 5)
			if len(splitStat) != 5 {
				return
			}
			ppid, err := strconv.Atoi(string(splitStat[3]))
			if err != nil {
				return
			}
			if ppid == 1 {
				return
			}

			if shouldBeTraced, ok := filter.PIDs[uint32(ppid)]; ok {
				trace := boolToUInt32(shouldBeTraced)
				processTreeBPFMap.Update(unsafe.Pointer(&pid), unsafe.Pointer(&trace))
				return
			}
			fn(uint32(ppid))
		}
		fn(uint32(pid))
	}

	for pid, shouldBeTraced := range filter.PIDs {
		trace := boolToUInt32(shouldBeTraced)
		processTreeBPFMap.Update(unsafe.Pointer(&pid), unsafe.Pointer(&trace))
	}

	return nil
}

func (filter *ProcessTreeFilter) FilterOut() bool {
	// Determine the default filter for PIDs that aren't specified with a proc tree filter
	// - If one or more '=' filters, default is '!='
	// - If one or more '!=' filters, default is '='
	// - If a mix of filters, the default is '='
	var filterIn = true
	for _, v := range filter.PIDs {
		filterIn = filterIn && v
	}
	return !filterIn
}

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

func (filter *ContIDFilter) Set(bpfModule *bpf.Module, conts *containers.Containers, filterMapName string) error {
	if !filter.Enabled {
		return nil
	}

	filterEqualU32 := uint32(filterEqual) // const need local var for bpfMap.Update()
	filterNotEqualU32 := uint32(filterNotEqual)

	filterMap, err := bpfModule.GetMap(filterMapName)
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

func (filter *ContIDFilter) FilterOut() bool {
	if len(filter.Equal) > 0 && len(filter.NotEqual) == 0 {
		return false
	} else {
		return true
	}
}

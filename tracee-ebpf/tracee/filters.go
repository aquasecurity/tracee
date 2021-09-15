package tracee

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

func (uintFilter *UintFilter) Parse(operatorAndValues string) error {
	uintFilter.Enabled = true
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
		if uintFilter.Is32Bit && (val > math.MaxUint32) {
			return fmt.Errorf("filter value is too big: %s", values[i])
		}
		switch operatorString {
		case "=":
			uintFilter.Equal = append(uintFilter.Equal, val)
		case "!=":
			uintFilter.NotEqual = append(uintFilter.NotEqual, val)
		case ">":
			if (uintFilter.Greater == GreaterNotSetUint) || (val > uintFilter.Greater) {
				uintFilter.Greater = val
			}
		case "<":
			if (uintFilter.Less == LessNotSetUint) || (val < uintFilter.Less) {
				uintFilter.Less = val
			}
		default:
			return fmt.Errorf("invalid filter operator: %s", operatorString)
		}
	}

	return nil
}

func (filter *UintFilter) Set(bpfModule *bpf.Module, filterMapName string, configFilter bpfConfig, lessIdx uint32) error {
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

	filterLessU32 := uint32(filter.Less)
	filterGreaterU32 := uint32(filter.Greater)

	// inequalityFilter filters events by some uint field either by < or >
	inequalityFilter, err := bpfModule.GetMap("inequality_filter") // u32, u64
	if err != nil {
		return err
	}
	if err = inequalityFilter.Update(unsafe.Pointer(&lessIdx), unsafe.Pointer(&filterLessU32)); err != nil {
		return err
	}
	lessIdxPlus := uint32(lessIdx + 1)
	if err = inequalityFilter.Update(unsafe.Pointer(&lessIdxPlus), unsafe.Pointer(&filterGreaterU32)); err != nil {
		return err
	}

	bpfConfigMap, err := bpfModule.GetMap("config_map") // u32, u32
	if err != nil {
		return err
	}
	if len(filter.Equal) > 0 && len(filter.NotEqual) == 0 && filter.Greater == GreaterNotSetUint && filter.Less == LessNotSetUint {
		filterInU32 := uint32(filterIn)
		err = bpfConfigMap.Update(unsafe.Pointer(&configFilter), unsafe.Pointer(&filterInU32))
	} else {
		filterOutU32 := uint32(filterOut)
		err = bpfConfigMap.Update(unsafe.Pointer(&configFilter), unsafe.Pointer(&filterOutU32))
	}

	return err
}

type IntFilter struct {
	Equal    []int64
	NotEqual []int64
	Greater  int64
	Less     int64
	Is32Bit  bool
	Enabled  bool
}

func (intFilter *IntFilter) Parse(operatorAndValues string) error {
	intFilter.Enabled = true
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
		if intFilter.Is32Bit && (val > math.MaxInt32) {
			return fmt.Errorf("filter value is too big: %s", values[i])
		}
		switch operatorString {
		case "=":
			intFilter.Equal = append(intFilter.Equal, val)
		case "!=":
			intFilter.NotEqual = append(intFilter.NotEqual, val)
		case ">":
			if (intFilter.Greater == GreaterNotSetInt) || (val > intFilter.Greater) {
				intFilter.Greater = val
			}
		case "<":
			if (intFilter.Less == LessNotSetInt) || (val < intFilter.Less) {
				intFilter.Less = val
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

func (stringFilter *StringFilter) Parse(operatorAndValues string) error {
	stringFilter.Enabled = true
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
			stringFilter.Equal = append(stringFilter.Equal, values[i])
		case "!=":
			stringFilter.NotEqual = append(stringFilter.NotEqual, values[i])
		default:
			return fmt.Errorf("invalid filter operator: %s", operatorString)
		}
	}

	return nil
}

func (filter *StringFilter) Set(bpfModule *bpf.Module, filterMapName string, configFilter bpfConfig) error {
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

	bpfConfigMap, err := bpfModule.GetMap("config_map") // u32, u32
	if err != nil {
		return err
	}
	if len(filter.Equal) > 0 && len(filter.NotEqual) == 0 {
		filterInU32 := uint32(filterIn)
		err = bpfConfigMap.Update(unsafe.Pointer(&configFilter), unsafe.Pointer(&filterInU32))
	} else {
		filterOutU32 := uint32(filterOut)
		err = bpfConfigMap.Update(unsafe.Pointer(&configFilter), unsafe.Pointer(&filterOutU32))
	}

	return err
}

type BoolFilter struct {
	Value   bool
	Enabled bool
}

func (boolFilter *BoolFilter) Parse(value string) error {
	boolFilter.Enabled = true
	boolFilter.Value = false
	if value[0] != '!' {
		boolFilter.Value = true
	}

	return nil
}

func (filter *BoolFilter) Set(bpfModule *bpf.Module, configFilter bpfConfig) error {
	if !filter.Enabled {
		return nil
	}

	bpfConfigMap, err := bpfModule.GetMap("config_map") // u32, u32
	if err != nil {
		return err
	}
	if filter.Value {
		filterInU32 := uint32(filterIn)
		err = bpfConfigMap.Update(unsafe.Pointer(&configFilter), unsafe.Pointer(&filterInU32))
	} else {
		filterOutU32 := uint32(filterOut)
		err = bpfConfigMap.Update(unsafe.Pointer(&configFilter), unsafe.Pointer(&filterOutU32))
	}

	return err
}

type RetFilter struct {
	Filters map[int32]IntFilter
	Enabled bool
}

func (retFilter *RetFilter) Parse(filterName string, operatorAndValues string, eventsNameToID map[string]int32) error {
	retFilter.Enabled = true
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

	if _, ok := retFilter.Filters[id]; !ok {
		retFilter.Filters[id] = IntFilter{
			Equal:    []int64{},
			NotEqual: []int64{},
			Less:     LessNotSetInt,
			Greater:  GreaterNotSetInt,
		}
	}

	intFilter := retFilter.Filters[id]

	// Treat operatorAndValues as an int filter to avoid code duplication
	err := (&intFilter).Parse(operatorAndValues)
	if err != nil {
		return err
	}

	retFilter.Filters[id] = intFilter

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

func (argFilter *ArgFilter) Parse(filterName string, operatorAndValues string, eventsNameToID map[string]int32) error {
	argFilter.Enabled = true
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

	eventParams, ok := EventsIDToParams[id]
	if !ok {
		return fmt.Errorf("invalid argument filter event name: %s", eventName)
	}

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

	if _, ok := argFilter.Filters[id]; !ok {
		argFilter.Filters[id] = make(map[string]ArgFilterVal)
	}

	if _, ok := argFilter.Filters[id][argName]; !ok {
		argFilter.Filters[id][argName] = ArgFilterVal{}
	}

	val := argFilter.Filters[id][argName]

	val.Equal = append(val.Equal, strFilter.Equal...)
	val.NotEqual = append(val.NotEqual, strFilter.NotEqual...)

	argFilter.Filters[id][argName] = val

	return nil
}

type ProcessTreeFilter struct {
	PIDs    map[uint32]bool // PIDs is a map where k=pid and v represents whether it and its descendents should be traced or not
	Enabled bool
}

func (procTreeFilter *ProcessTreeFilter) Parse(operatorAndValues string) error {
	procTreeFilter.Enabled = true

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
		procTreeFilter.PIDs[uint32(pid)] = equalityOperator
	}

	return nil
}

func (filter *ProcessTreeFilter) Set(bpfModule *bpf.Module) error {
	if !filter.Enabled {
		return nil
	}

	// Determine the default filter for PIDs that aren't specified with a proc tree filter
	// - If one or more '=' filters, default is '!='
	// - If one or more '!=' filters, default is '='
	// - If a mix of filters, the default is '='
	var defaultFilter = true
	for _, v := range filter.PIDs {
		defaultFilter = defaultFilter && v
	}
	err := (&BoolFilter{Value: defaultFilter, Enabled: true}).Set(bpfModule, configProcTreeFilter)
	if err != nil {
		return fmt.Errorf("could not set default process tree filter value: %v", err)
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

package filters

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils"
)

type ProcessTreeFilter struct {
	PIDs    map[uint32]bool // PIDs is a map where k=pid and v represents whether it and its descendent should be traced or not
	enabled bool
	mapName string
}

func NewProcessTreeFilter(mapName string) *ProcessTreeFilter {
	return &ProcessTreeFilter{
		PIDs:    map[uint32]bool{},
		enabled: false,
		mapName: mapName,
	}
}

func (f *ProcessTreeFilter) Enable() {
	f.enabled = true
}

func (f *ProcessTreeFilter) Disable() {
	f.enabled = false
}

func (f *ProcessTreeFilter) Enabled() bool {
	return f.enabled
}

func (filter *ProcessTreeFilter) Parse(operatorAndValues string) error {
	if len(operatorAndValues) < 2 {
		return InvalidExpression(operatorAndValues)
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
			return errfmt.Errorf("no value passed with operator in process tree filter")
		}
		equalityOperator = false
	} else {
		return InvalidExpression(operatorAndValues)
	}

	values := strings.Split(valuesString, ",")
	for _, value := range values {
		pid, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return errfmt.Errorf("invalid PID given to filter: %s", valuesString)
		}
		filter.PIDs[uint32(pid)] = equalityOperator
	}

	filter.Enable()

	return nil
}

func (filter *ProcessTreeFilter) UpdateBPF(bpfModule *bpf.Module, policyID uint) error {
	if !filter.Enabled() {
		return nil
	}

	processTreeBPFMap, err := bpfModule.GetMap(filter.mapName)
	if err != nil {
		return errfmt.Errorf("could not find bpf process_tree_map: %v", err)
	}

	procDir, err := os.Open("/proc")
	if err != nil {
		return errfmt.Errorf("could not open proc dir: %v", err)
	}
	defer func() {
		if err := procDir.Close(); err != nil {
			logger.Errorw("Closing file", "error", err)
		}
	}()

	entries, err := procDir.Readdirnames(-1)
	if err != nil {
		return errfmt.Errorf("could not read proc dir: %v", err)
	}

	updateBPF := func(shouldBeTraced bool, pid uint64) {
		filterVal := make([]byte, 16)
		var equalInPolicies, equalitySetInPolicies uint64
		curVal, err := processTreeBPFMap.GetValue(unsafe.Pointer(&pid))
		if err == nil {
			equalInPolicies = binary.LittleEndian.Uint64(curVal[0:8])
			equalitySetInPolicies = binary.LittleEndian.Uint64(curVal[8:16])
		}

		if shouldBeTraced {
			utils.SetBit(&equalInPolicies, policyID)
		} else {
			utils.ClearBit(&equalInPolicies, policyID)
		}
		utils.SetBit(&equalitySetInPolicies, policyID)

		binary.LittleEndian.PutUint64(filterVal[0:8], equalInPolicies)
		binary.LittleEndian.PutUint64(filterVal[8:16], equalitySetInPolicies)
		err = processTreeBPFMap.Update(unsafe.Pointer(&pid), unsafe.Pointer(&filterVal[0]))
		if err != nil {
			logger.Errorw("Updating processTreeBPFMap", "error", err)
		}
	}

	// Iterate over each pid
	for _, entry := range entries {
		pid, err := strconv.ParseUint(entry, 10, 32)
		if err != nil {
			continue
		}
		var fn func(uint32)
		fn = func(curPid uint32) {
			stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", curPid))
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
				updateBPF(shouldBeTraced, pid)
				return
			}
			fn(uint32(ppid))
		}
		fn(uint32(pid))
	}

	for pid, shouldBeTraced := range filter.PIDs {
		updateBPF(shouldBeTraced, uint64(pid))
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

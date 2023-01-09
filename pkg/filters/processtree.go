package filters

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/tracee/pkg/logger"
)

type ProcessTreeFilter struct {
	PIDs    map[uint32]bool // PIDs is a map where k=pid and v represents whether it and its descendents should be traced or not
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
			return fmt.Errorf("no value passed with operator in process tree filter")
		}
		equalityOperator = false
	} else {
		return InvalidExpression(operatorAndValues)
	}

	values := strings.Split(valuesString, ",")
	for _, value := range values {
		pid, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return fmt.Errorf("invalid PID given to filter: %s", valuesString)
		}
		filter.PIDs[uint32(pid)] = equalityOperator
	}

	filter.Enable()

	return nil
}

func (filter *ProcessTreeFilter) InitBPF(bpfModule *bpf.Module) error {
	if !filter.Enabled() {
		return nil
	}

	processTreeBPFMap, err := bpfModule.GetMap(filter.mapName)
	if err != nil {
		return fmt.Errorf("could not find bpf process_tree_map: %v", err)
	}

	procDir, err := os.Open("/proc")
	if err != nil {
		return fmt.Errorf("could not open proc dir: %v", err)
	}
	defer func() {
		err := procDir.Close()
		if err != nil {
			logger.Error("Closing file", "error", err)
		}
	}()

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
				err = processTreeBPFMap.Update(unsafe.Pointer(&pid), unsafe.Pointer(&trace))
				if err != nil {
					logger.Error("Updating processTreeBPFMap", "error", err)
				}
				return
			}
			fn(uint32(ppid))
		}
		fn(uint32(pid))
	}

	for pid, shouldBeTraced := range filter.PIDs {
		trace := boolToUInt32(shouldBeTraced)
		err := processTreeBPFMap.Update(unsafe.Pointer(&pid), unsafe.Pointer(&trace))
		if err != nil {
			return err
		}
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

func boolToUInt32(b bool) uint32 {
	if b {
		return uint32(1)
	}
	return uint32(0)
}

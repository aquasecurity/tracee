package filters

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/tracee/types/protocol"
)

type ProcessTreeFilter struct {
	PIDs    map[uint32]bool // PIDs is a map where k=pid and v represents whether it and its descendents should be traced or not
	Enabled bool
}

func (filter *ProcessTreeFilter) Add(filterReq protocol.Filter) error {
	filter.Enabled = true

	for _, value := range filterReq.Value {
		pid, err := strconv.ParseUint(fmt.Sprint(value), 10, 32)
		if err != nil {
			return fmt.Errorf("invalid PID given to filter: %s", value)
		}
		switch filterReq.Operator {
		case protocol.Equal:
			filter.PIDs[uint32(pid)] = true
		case protocol.NotEqual:
			filter.PIDs[uint32(pid)] = false
		default:
			return fmt.Errorf("invalid operator given to tree filter %s", filterReq.Operator.String())
		}
	}

	return nil
}

func (filter *ProcessTreeFilter) InitBpf(bpfModule *bpf.Module) error {
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

func boolToUInt32(b bool) uint32 {
	if b {
		return uint32(1)
	}
	return uint32(0)
}

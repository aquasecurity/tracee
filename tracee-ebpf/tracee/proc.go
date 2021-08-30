package tracee

import (
	"github.com/prometheus/procfs"
)

func gatherEntireProcessTree() (map[uint32][]uint32, error) {
	fs, err := procfs.NewFS("/proc")
	if err != nil {
		return nil, err
	}

	procs, err := fs.AllProcs()
	if err != nil {
		return nil, err
	}

	processMap := map[uint32][]uint32{}
	for i := range procs {
		stat, err := procs[i].Stat()
		if err != nil {
			return nil, err
		}
		processMap[uint32(stat.PID)] = processMap[uint32(stat.PID)]
		processMap[uint32(stat.PPID)] = append(processMap[uint32(stat.PPID)], uint32(stat.PID))
	}

	return processMap, nil
}

// populateProcessTreeFilterMap takes a map of the process tree (k=ppid, v=[]childpid)
// and a filter specification map (k=pid,v=trace/not) and returns a fully populated map
// where k=pid, v=trace/not for all pids
func populateProcessTreeFilterMap(processTree map[uint32][]uint32,
	filterSpecification map[uint32]bool) map[uint32]bool {

	filterMap := map[uint32]bool{}

	// Determine the default filter for PIDs that aren't specified with a proc tree filter
	// - If one or more '=' filters, default is '!='
	// - If one or more '!=' filters, default is '='
	// - If a mix of filters, the default is '='
	var defaultFilter = true
	for _, v := range filterSpecification {
		defaultFilter = defaultFilter && v
	}
	defaultFilter = !defaultFilter

	// Populate inital filter map  (keys representing all pids)
	for pid, _ := range processTree {
		filterMap[pid] = defaultFilter
	}

	// Iterate over each pid
	for pid, _ := range filterMap {

		// Check if there's a filter specified for this pid and apply to its descendents
		if shouldBeTraced, ok := filterSpecification[pid]; ok {
			descendentPIDs := gatherAllDescedentPIDs(pid, processTree)

			if shouldBeTraced {
				for j := range descendentPIDs {
					filterMap[descendentPIDs[j]] = true
				}
			} else if !shouldBeTraced {
				for j := range descendentPIDs {
					filterMap[descendentPIDs[j]] = false
				}
			}
		}
	}

	return filterMap
}

// gatherAllDescedentPIDs takes a specific pid, and a map 'pids' which represents
// a snapshot of the process tree where k = ppid and v = slice of child pids
// and returns a slice of all the descedent pids
func gatherAllDescedentPIDs(pid uint32, pids map[uint32][]uint32) []uint32 {

	allDescendents := []uint32{pid}

	for _, p := range pids[pid] {
		allDescendents = append(allDescendents, gatherAllDescedentPIDs(p, pids)...)
	}
	return allDescendents
}

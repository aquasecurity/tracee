package tracee

import (
	"github.com/prometheus/procfs"
)

// gatherProcessTreeMap takes a particular PID and a boolean which represents whether or not it's descedent
// PIDs should be traced or not. The returns map is a snapshot of the process tree and w
func gatherProcessTreeMap(filteredPID uint32, processTreeFilterEquality bool) (map[uint32]bool, error) {
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
		processMap[uint32(stat.PPID)] = append(processMap[uint32(stat.PPID)], uint32(stat.PID))
	}

	descendentPIDs := gatherAllDescedentPIDs(filteredPID, processMap)

	filterMap := map[uint32]bool{
		filteredPID: processTreeFilterEquality,
	}

	for i := range procs {
		isDescendent := false
		for j := range descendentPIDs {
			if descendentPIDs[j] == uint32(procs[i].PID) {
				isDescendent = true
			}
		}
		filterMap[uint32(procs[i].PID)] = processTreeFilterEquality && isDescendent
	}

	return filterMap, nil
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

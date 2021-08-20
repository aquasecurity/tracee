package tracee

import (
	"github.com/prometheus/procfs"
)

// gatherProcessTreeMap will put all PIDs into the returned map that are
// children of filteredPID
func gatherProcessTreeMap(filteredPID uint32) (map[uint32]uint32, error) {
	fs, err := procfs.NewFS("/proc")
	if err != nil {
		return nil, err
	}

	procs, err := fs.AllProcs()
	if err != nil {
		return nil, err
	}

	filterPidAndChildPids := map[uint32]uint32{
		filteredPID: 1,
	}

	processMap := map[uint32][]uint32{}
	for i := range procs {
		stat, err := procs[i].Stat()
		if err != nil {
			return nil, err
		}
		processMap[uint32(stat.PPID)] = append(processMap[uint32(stat.PPID)], uint32(stat.PID))
	}

	pids := gatherEachPidChildPids(filteredPID, processMap)

	for _, p := range pids {
		filterPidAndChildPids[p] = 1
	}

	return filterPidAndChildPids, nil
}

func gatherEachPidChildPids(pid uint32, pids map[uint32][]uint32) []uint32 {

	allDescendents := []uint32{pid}

	for _, p := range pids[pid] {
		allDescendents = append(allDescendents, gatherEachPidChildPids(p, pids)...)
	}
	return allDescendents
}

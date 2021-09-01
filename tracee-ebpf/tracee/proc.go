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
			continue // proc likely exited while iterating over proc, can ignore
		}
		processMap[uint32(stat.PID)] = processMap[uint32(stat.PID)]
		processMap[uint32(stat.PPID)] = append(processMap[uint32(stat.PPID)], uint32(stat.PID))
	}

	return processMap, nil
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

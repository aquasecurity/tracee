package tracee

import (
	"github.com/prometheus/procfs"
)

func gatherProcessTreeMap() (map[int]int, error) {
	fs, err := procfs.NewFS("/proc")
	if err != nil {
		return nil, err
	}

	procs, err := fs.AllProcs()
	if err != nil {
		return nil, err
	}

	var (
		stat   procfs.ProcStat
		pidMap = make(map[int]int)
	)
	for i := range procs {
		stat, err = procs[i].Stat()
		if err != nil {
			return nil, err
		}
		pidMap[stat.PID] = stat.PPID
	}

	return pidMap, nil
}

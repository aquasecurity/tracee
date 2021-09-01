package tracee

import (
	"github.com/prometheus/procfs"
)

func getPPIDMap() (map[uint32]uint32, error) {
	fs, err := procfs.NewFS("/proc")
	if err != nil {
		return nil, err
	}

	procs, err := fs.AllProcs()
	if err != nil {
		return nil, err
	}

	procPPIDMap := map[uint32]uint32{}
	for i := range procs {
		stat, err := procs[i].Stat()
		if err != nil {
			continue // proc likely exited while iterating over proc, can ignore
		}
		procPPIDMap[uint32(stat.PID)] = uint32(stat.PPID)
	}

	return procPPIDMap, nil
}

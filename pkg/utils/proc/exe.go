package proc

import (
	"os"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
)

// GetProcNS returns the namespace ID of a given namespace and process.
// To do so, it requires access to the /proc file system of the host, and CAP_SYS_PTRACE capability.
func GetProcBinary(pid int32) (string, error) {
	exePath := GetProcExePath(pid)
	binPath, err := os.Readlink(exePath)
	if err != nil {
		return "", errfmt.Errorf("could not read exe file: %v", err)
	}

	return binPath, nil
}

// GetProcNS returns the namespace ID of a given namespace and process.
// To do so, it requires access to the /proc file system of the host, and CAP_SYS_PTRACE capability.
func GetAllBinaryProcs() (map[string][]int32, error) { // map[binpath]pids
	procDir, err := os.Open("/proc")
	if err != nil {
		return nil, errfmt.Errorf("could not open procfs dir: %v", err)
	}
	defer func() {
		if err := procDir.Close(); err != nil {
			logger.Errorw("Closing file", "error", err)
		}
	}()

	procs, err := procDir.Readdirnames(-1)
	if err != nil {
		return nil, errfmt.Errorf("could not open procfs dir: %v", err)
	}

	binProcs := map[string][]int32{}
	for _, proc := range procs {
		pid, err := ParseInt32(proc)
		if err != nil {
			continue
		}
		bin, _ := GetProcBinary(pid)
		if _, ok := binProcs[bin]; !ok {
			binProcs[bin] = []int32{}
		}
		binProcs[bin] = append(binProcs[bin], pid)
	}

	return binProcs, nil
}

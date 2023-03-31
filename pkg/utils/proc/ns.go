package proc

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
)

// GetMountNSFirstProcesses return mapping between mount NS to its first process
// (aka, the process with the oldest start time in the mount NS)
func GetMountNSFirstProcesses() (map[int]int, error) {
	procDir, err := os.Open("/proc")
	if err != nil {
		return nil, errfmt.Errorf("could not open proc dir: %v", err)
	}
	defer func() {
		if err := procDir.Close(); err != nil {
			logger.Errorw("Closing file", "error", err)
		}
	}()

	entries, err := procDir.Readdirnames(-1)
	if err != nil {
		return nil, errfmt.Errorf("could not read proc dir: %v", err)
	}

	type pidTimestamp struct {
		pid       uint
		timestamp int
	}
	mountNSTimeMap := make(map[int]pidTimestamp)
	// Iterate over each pid
	for _, entry := range entries {
		pid, err := strconv.ParseUint(entry, 10, 32)
		if err != nil {
			continue
		}
		procNS, err := GetAllProcNS(uint(pid))
		if err != nil {
			logger.Debugw("Failed in fetching process mount namespace", "pid", pid, "error", err.Error())
			continue
		}

		processStartTime, err := GetProcessStartTime(uint(pid))
		if err != nil {
			logger.Debugw("Failed in fetching process start time", "pid", pid, "error", err.Error())
			continue
		}

		currentNSProcess, ok := mountNSTimeMap[procNS.Mnt]
		if ok {
			// If executed after current save process, it can't be the first process
			if processStartTime >= currentNSProcess.timestamp {
				continue
			}
		}
		mountNSTimeMap[procNS.Mnt] = pidTimestamp{timestamp: processStartTime, pid: uint(pid)}
	}

	mountNSToFirstProcess := make(map[int]int)
	for mountNS, p := range mountNSTimeMap {
		mountNSToFirstProcess[mountNS] = int(p.pid)
	}
	return mountNSToFirstProcess, nil
}

// GetProcessStartTime return the start time of the process using the procfs
func GetProcessStartTime(pid uint) (int, error) {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, errfmt.WrapError(err)
	}
	// see https://man7.org/linux/man-pages/man5/proc.5.html for how to read /proc/pid/stat
	startTimeOffset := 22 // Offset start at 1
	commOffset := 2
	// We want to remove the comm from the string, because it can contain a space which will change the offsets after split
	splitByComm := bytes.SplitN(stat, []byte{')', ' '}, 2)
	if len(splitByComm) != 2 {
		return 0, errfmt.Errorf("error in parsing /proc/<pid>/stat format - comm name is not surrounded by parentheses as expected")
	}
	newStartTimeOffset := startTimeOffset - commOffset
	splitStat := bytes.SplitN(splitByComm[1], []byte{' '}, newStartTimeOffset+1)
	if len(splitStat) != newStartTimeOffset+1 {
		return 0, errfmt.Errorf("error in parsing /proc/<pid>/stat format - only %d values found inside", len(splitStat))
	}
	startTime, err := strconv.Atoi(string(splitStat[newStartTimeOffset-1]))
	if err != nil {
		return 0, errfmt.WrapError(err)
	}

	return startTime, nil
}

type ProcNS struct {
	Cgroup          int
	Ipc             int
	Mnt             int
	Net             int
	Pid             int
	PidForChildren  int
	Time            int
	TimeForChildren int
	User            int
	Uts             int
}

// GetAllProcNS return all the namespaces of a given process.
// To do so, it requires access to the /proc file system of the host, and CAP_SYS_PTRACE capability.
func GetAllProcNS(pid uint) (*ProcNS, error) {
	nsDir, err := os.Open(fmt.Sprintf("/proc/%d/ns", pid))
	if err != nil {
		return nil, errfmt.Errorf("could not open ns dir: %v", err)
	}
	defer func() {
		if err := nsDir.Close(); err != nil {
			logger.Errorw("Closing file", "error", err)
		}
	}()

	entries, err := nsDir.Readdirnames(-1)
	if err != nil {
		return nil, errfmt.Errorf("could not read ns dir: %v", err)
	}

	var procNS ProcNS
	for _, entry := range entries {
		nsLink, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/%s", pid, entry))
		if err != nil {
			return nil, errfmt.WrapError(err)
		}
		ns, err := extractNSFromLink(nsLink)
		if err != nil {
			return nil, errfmt.WrapError(err)
		}
		switch entry {
		case "cgroup":
			procNS.Cgroup = ns
		case "ipc":
			procNS.Ipc = ns
		case "mnt":
			procNS.Mnt = ns
		case "net":
			procNS.Net = ns
		case "pid":
			procNS.Pid = ns
		case "pid_for_children":
			procNS.PidForChildren = ns
		case "time":
			procNS.Time = ns
		case "time_for_children":
			procNS.TimeForChildren = ns
		case "user":
			procNS.User = ns
		case "uts":
			procNS.Uts = ns
		default:
			return nil, errfmt.Errorf("encountered unexpected namespace file - %s", entry)
		}
	}
	return &procNS, nil
}

// GetProcNS returns the namespace ID of a given namespace and process.
// To do so, it requires access to the /proc file system of the host, and CAP_SYS_PTRACE capability.
func GetProcNS(pid uint, nsName string) (int, error) {
	nsLink, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/%s", pid, nsName))
	if err != nil {
		return 0, errfmt.Errorf("could not read ns file: %v", err)
	}
	ns, err := extractNSFromLink(nsLink)
	if err != nil {
		return 0, errfmt.Errorf("could not extract ns id: %v", err)
	}
	return ns, nil
}

func extractNSFromLink(link string) (int, error) {
	nsLinkSplitted := strings.SplitN(link, ":[", 2)
	if len(nsLinkSplitted) != 2 {
		return 0, errfmt.Errorf("link format is not supported")
	}
	nsString := strings.TrimSuffix(nsLinkSplitted[1], "]")
	ns, err := strconv.Atoi(nsString)
	if err != nil {
		return 0, errfmt.WrapError(err)
	}
	return ns, nil
}

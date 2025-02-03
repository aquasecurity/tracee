package proc

import (
	"os"
	"strings"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
)

// https://elixir.bootlin.com/linux/v6.13/source/include/linux/ns_common.h#L12
// struct ns_common inum member is unsigned int
type ProcNS struct {
	Cgroup          uint32
	Ipc             uint32
	Mnt             uint32
	Net             uint32
	Pid             uint32
	PidForChildren  uint32
	Time            uint32
	TimeForChildren uint32
	User            uint32
	Uts             uint32
}

// GetAllProcNS return all the namespaces of a given process.
// To do so, it requires access to the /proc file system of the host, and CAP_SYS_PTRACE capability.
func GetAllProcNS(pid int32) (*ProcNS, error) {
	nsDirPath := GetProcNSDirPath(pid)
	nsDir, err := os.Open(nsDirPath)
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

	// namespace mapping to avoid branching and reduce function size
	nsMap := map[string]*uint32{
		"cgroup":            &procNS.Cgroup,
		"ipc":               &procNS.Ipc,
		"mnt":               &procNS.Mnt,
		"net":               &procNS.Net,
		"pid":               &procNS.Pid,
		"pid_for_children":  &procNS.PidForChildren,
		"time":              &procNS.Time,
		"time_for_children": &procNS.TimeForChildren,
		"user":              &procNS.User,
		"uts":               &procNS.Uts,
	}

	for _, entry := range entries {
		entryNSPath := nsDirPath + "/" + entry // /proc/<pid>/ns/<entry>
		nsLink, err := os.Readlink(entryNSPath)
		if err != nil {
			return nil, errfmt.WrapError(err)
		}

		ns, err := extractNSFromLink(nsLink)
		if err != nil {
			return nil, errfmt.WrapError(err)
		}

		nsPtr, ok := nsMap[entry]
		if !ok {
			return nil, errfmt.Errorf("encountered unexpected namespace file - %s", entry)
		}

		*nsPtr = ns
	}

	return &procNS, nil
}

// GetProcNS returns the namespace ID of a given namespace and process.
// To do so, it requires access to the /proc file system of the host, and CAP_SYS_PTRACE capability.
func GetProcNS(pid int32, nsName string) (uint32, error) {
	nsPath := GetProcNSPath(pid, nsName)
	nsLink, err := os.Readlink(nsPath)
	if err != nil {
		return 0, errfmt.Errorf("could not read ns file: %v", err)
	}

	ns, err := extractNSFromLink(nsLink)
	if err != nil {
		return 0, errfmt.Errorf("could not extract ns id: %v", err)
	}

	return ns, nil
}

func extractNSFromLink(link string) (uint32, error) {
	startIdx := strings.IndexByte(link, '[')
	if startIdx == -1 {
		return 0, errfmt.Errorf("link format is not supported")
	}

	// assume that the namespace ID is the content between the first '[' and the last ']'
	nsString := link[startIdx+1 : len(link)-1]
	ns, err := ParseUint32(nsString)
	if err != nil {
		return 0, errfmt.Errorf("invalid namespace ID %s: %v", nsString, err)
	}

	return ns, nil
}

// GetMountNSFirstProcesses return mapping between mount NS to its first process
// (aka, the process with the oldest start time in the mount NS)
func GetMountNSFirstProcesses() (map[uint32]int32, error) { // map[mountNS]pid
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
		pid       int32
		timestamp uint64
	}
	mountNSTimeMap := make(map[uint32]pidTimestamp)

	// Iterate over each pid
	for _, entry := range entries {
		pid, err := ParseInt32(entry)
		if err != nil {
			continue
		}

		procNS, err := GetAllProcNS(pid)
		if err != nil {
			logger.Debugw("Failed in fetching process mount namespace", "pid", pid, "error", err.Error())
			continue
		}

		procStat, err := NewProcStatFields(
			pid,
			[]StatField{
				StatStartTime,
			},
		)
		if err != nil {
			logger.Debugw("Failed in fetching process start time", "pid", pid, "error", err.Error())
			continue
		}
		processStartTime := procStat.GetStartTime()

		currentNSProcess, ok := mountNSTimeMap[procNS.Mnt]
		if ok {
			// If executed after current save process, it can't be the first process
			if processStartTime >= currentNSProcess.timestamp {
				continue
			}
		}
		mountNSTimeMap[procNS.Mnt] = pidTimestamp{
			timestamp: processStartTime,
			pid:       pid,
		}
	}

	mountNSToFirstProcess := make(map[uint32]int32)
	for mountNS, p := range mountNSTimeMap {
		mountNSToFirstProcess[mountNS] = p.pid
	}

	return mountNSToFirstProcess, nil
}

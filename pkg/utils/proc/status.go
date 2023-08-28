package proc

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

//
// ProcStatus: /proc/[pid]/status
//

// Most common fields from /proc/[pid]/status file:
//
// Name           string   // Name of the process
// State          string   // State of the process
// Tgid           int      // Thread group ID
// Ngid           int      // NUMA group ID (if available)
// Pid            int      // Process ID
// PPid           int      // Parent Process ID
// TracerPid      int      // PID of process tracing this process
// Uid            [4]int   // Real, effective, saved set, and filesystem UIDs
// Gid            [4]int   // Real, effective, saved set, and filesystem GIDs
// FDSize         int      // Number of file descriptor slots currently allocated
// Groups         []int    // Supplementary group list
// VmPeak         int64    // Peak virtual memory size
// VmSize         int64    // Total program size
// VmLck          int64    // Locked memory size
// VmPin          int64    // Pinned memory size (guaranteed never to be swapped out)
// VmHWM          int64    // Peak resident set size ("high water mark")
// VmRSS          int64    // Resident set size
// VmData         int64    // Size of data
// VmStk          int64    // Size of stack
// VmExe          int64    // Size of text segments
// VmLib          int64    // Shared library code size
// VmPTE          int64    // Page table entries size
// VmSwap         int64    // Swap size
// Threads        int      // Number of threads in process
//
// ...

type ProcStatus map[string]string

func NewThreadProcStatus(pid, tid int) (*ProcStatus, error) {
	filePath := fmt.Sprintf("/proc/%v/task/%v/status", pid, tid)
	return newProcStatus(filePath)
}

func NewProcStatus(pid int) (*ProcStatus, error) {
	filePath := fmt.Sprintf("/proc/%v/status", pid)
	return newProcStatus(filePath)
}

func newProcStatus(filePath string) (*ProcStatus, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()

	status := make(ProcStatus)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		status[key] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return &status, nil
}

// GetName returns name of the process.
func (ps ProcStatus) GetName() string {
	return ps["Name"]
}

// GetState returns state of the process.
func (ps ProcStatus) GetState() string {
	return ps["State"]
}

// GetTgid returns thread group ID.
func (ps ProcStatus) GetTgid() int {
	return ps.getInt("Tgid")
}

// GetPid returns process ID.
func (ps ProcStatus) GetPid() int {
	return ps.getInt("Pid")
}

// GetPPid returns parent process ID.
func (ps ProcStatus) GetPPid() int {
	return ps.getInt("PPid")
}

// GetNsTgid returns thread group ID in the namespace of the process.
func (ps ProcStatus) GetNsTgid() int {
	return ps.getInt("NStgid")
}

// GetNsPid returns process ID in the namespace of the process.
func (ps ProcStatus) GetNsPid() int {
	return ps.getInt("NSpid")
}

// GetNsPPid returns parent process ID in the namespace of the process.
func (ps ProcStatus) GetNsPPid() int {
	return ps.getInt("NSpgid")
}

// GetThreads returns number of threads in process.
func (ps ProcStatus) GetThreads() int {
	return ps.getInt("Threads")
}

// GetUid returns UID in the following order: real, effective, saved set, filesystem.
func (ps ProcStatus) GetUid() [4]int {
	uids := [4]int{}
	parts := strings.Fields(ps["Uid"])
	for i, part := range parts {
		uids[i], _ = strconv.Atoi(part)
	}
	return uids
}

// GetGid returns GID in the following order: real, effective, saved set, filesystem.
func (ps ProcStatus) GetGid() [4]int {
	gids := [4]int{}
	parts := strings.Fields(ps["Gid"])
	for i, part := range parts {
		gids[i], _ = strconv.Atoi(part)
	}
	return gids
}

// getInt returns integer value of the given key.
func (ps ProcStatus) getInt(key string) int {
	val, err := strconv.Atoi(ps[key])
	if err != nil {
		return 0
	}
	return val
}

// getInt64 returns int64 value of the given key.
func (ps ProcStatus) getInt64(key string) int64 {
	val, err := strconv.ParseInt(ps[key], 10, 64)
	if err != nil {
		return 0
	}
	return val
}

package proc

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
)

//
// ProcStatus
// https://elixir.bootlin.com/linux/v6.11.4/source/fs/proc/array.c#L439
//

// Most common fields from /proc/<pid>/[task/<tid>/]status file:
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
// NStgid         int      // Thread group ID in the namespace of the process
// NSpid          int      // Process ID in the namespace of the process
// NSpgid         int      // Process group ID in the namespace of the process
// NSsid          int      // Session ID in the namespace of the process
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

// ProcStatus represents the minimal required fields of the /proc status file.
type ProcStatus struct {
	name   string // up to 64 chars: https://elixir.bootlin.com/linux/v6.11.4/source/fs/proc/array.c#L99
	tgid   int
	pid    int
	pPid   int
	nstgid int
	nspid  int
	nspgid int
}

type procStatusValueParser func(value string, s *ProcStatus)

// procStatusValueParserMap maps the keys in the status file to their respective value parsers.
// If a key is not present in the map, it is ignored on parsing.
var procStatusValueParserMap = map[string]procStatusValueParser{ // key: status file key, value: parser function
	"Name":   parseName,
	"Tgid":   parseTgid,
	"Pid":    parsePid,
	"PPid":   parsePPid,
	"NStgid": parseNsTgid,
	"NSpid":  parseNsPid,
	"NSpgid": parseNsPgid,
}

// NewThreadProcStatus reads the /proc/<pid>/task/<tid>/status file and parses it into a ProcStatus struct.
func NewThreadProcStatus(pid, tid int) (*ProcStatus, error) {
	filePath := fmt.Sprintf("/proc/%v/task/%v/status", pid, tid)
	return newProcStatus(filePath)
}

// NewProcStatus reads the /proc/<pid>/status file and parses it into a ProcStatus struct.
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

	status := &ProcStatus{}
	remainingFields := len(procStatusValueParserMap)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Bytes()
		parts := bytes.SplitN(line, []byte(":"), 2)
		if len(parts) < 2 {
			continue
		}
		key := parts[0]
		value := bytes.TrimSpace(parts[1])

		parseValue, ok := procStatusValueParserMap[string(key)]
		if !ok {
			// unknown key or not required, see procStatusValueParserMap and ProcStatus struct
			continue
		}

		parseValue(string(value), status)
		remainingFields--
		if remainingFields == 0 {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return status, nil
}

// status fields parsers

func parseName(value string, s *ProcStatus) {
	s.name = parseString(value)
}

func parseTgid(value string, s *ProcStatus) {
	s.tgid = parseInt(value)
}

func parsePid(value string, s *ProcStatus) {
	s.pid = parseInt(value)
}

func parsePPid(value string, s *ProcStatus) {
	s.pPid = parseInt(value)
}

func parseNsTgid(value string, s *ProcStatus) {
	s.nstgid = parseInt(value)
}

func parseNsPid(value string, s *ProcStatus) {
	s.nspid = parseInt(value)
}

func parseNsPgid(value string, s *ProcStatus) {
	s.nspgid = parseInt(value)
}

//
// Public methods
//

// GetName returns the name of the process.
func (s *ProcStatus) GetName() string {
	return s.name
}

// GetPid returns the process ID.
func (s *ProcStatus) GetPid() int {
	return s.pid
}

// GetTgid returns the thread group ID.
func (s *ProcStatus) GetTgid() int {
	return s.tgid
}

// GetPPid returns the parent process ID.
func (s *ProcStatus) GetPPid() int {
	return s.pPid
}

// GetNsPid returns process ID in the namespace of the process.
func (s *ProcStatus) GetNsPid() int {
	return s.nspid
}

// GetNsTgid returns thread group ID in the namespace of the process.
func (s *ProcStatus) GetNsTgid() int {
	return s.nstgid
}

// GetNsPPid returns process group ID in the namespace of the process.
func (s *ProcStatus) GetNsPPid() int {
	return s.nspgid
}

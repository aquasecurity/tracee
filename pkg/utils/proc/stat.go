package proc

import (
	"bytes"
	"fmt"
	"os"
)

//
// ProcStat
// https://elixir.bootlin.com/linux/v6.11.4/source/fs/proc/array.c#L467
//

// Fields from /proc/<pid>/[task/<tid>/]stat file:
//
// Pid                 int    // process id
// Comm                string // the filename of the executable
// State               byte   // process state
// Ppid                int    // parent process id
// Pgrp                int    // process group id
// Session             int    // session id
// TtyNr               int    // controlling terminal
// Tpgid               int    // foreground process group id of the controlling terminal
// Flags               uint64 // process flags
// MinFlt              uint64 // number of minor faults
// CminFlt             uint64 // number of minor faults (all childs)
// MajFlt              uint64 // number of major faults
// CmajFlt             uint64 // number of major faults (all childs)
// Utime               uint64 // user mode jiffies (clock ticks)
// Stime               uint64 // kernel mode jiffies (clock ticks)
// Cutime              int64  // user mode jiffies (all childs)
// Cstime              int64  // kernel mode jiffies (all childs)
// Priority            int    // process priority
// Nice                int    // process nice value
// NumThreads          int    // number of threads in this process
// ItRealValue         uint64 // (obsolete, always 0)
// StartTime           uint64 // time the process started after system boot (in clock ticks)
// Vsize               uint64 // virtual memory size
// Rss                 uint64 // resident set memory size
// Rsslim              uint64 // current limit in bytes on the rss
// Startcode           int64  // address above which program text can run
// Endcode             int64  // address below which program text can run
// StartStack          int64  // address of the start of the main process stack
// Kstkesp             int64  // current value of stack pointer
// Kstkeip             int64  // current value of instruction pointer
// Signal              uint64 // bitmap of pending signals
// Blocked             uint64 // bitmap of blocked signals
// SigIgnore           uint64 // bitmap of ignored signals
// Sigcatch            uint64 // bitmap of catched signals
// Wchan               int64  // address of the syscall where process is in sleep mode
// Nswap               int64  // number of swapped pages
// Cnswap              int64  // cumulative nswap for child processes
// ExitSignal          int    // signal to be sent to parent when we die
// Processor           int    // current CPU
// RtPriority          int    // realtime priority
// Policy              int    // scheduling policy
// DelayacctBlkioTicks int64  // time spent waiting for block IO
// GuestTime           int64  // guest time of the process
// CguestTime          int64  // guest time of the process's children
// StartData           int64  // address above which program data+bss is placed
// EndData             int64  // address below which program data+bss is placed
// StartBrk            int64  // address above which program heap can be expanded with brk()
// ArgStart            int64  // address above which program command line is placed
// ArgEnd              int64  // address below which program command line is placed
// EnvStart            int64  // address above which program environment is placed
// EnvEnd              int64  // address below which program environment is placed
// ExitCode            int    // the thread's exit_code in the form reported by the waitpid system call

const (
	StatNumFields = 52
)

// ProcStat represents the minimal required fields of the /proc stat file.
type ProcStat struct {
	startTime uint64 // time the process started after system boot (in clock ticks)
}

type procStatValueParser func(value string, s *ProcStat)

// procStatValueParserArray maps the index of the field in the stat file to its respective value parser.
// If a parser is nil, the field is ignored on parsing.
var procStatValueParserArray = [StatNumFields]procStatValueParser{
	21: parseStartTime, // StartTime
}

// NewThreadProcStat reads the /proc/<pid>/task/<tid>/stat file and parses it into a ProcStat struct.
func NewThreadProcStat(pid, tid int) (*ProcStat, error) {
	filepath := fmt.Sprintf("/proc/%v/task/%v/stat", pid, tid)
	return newProcStat(filepath)
}

// NewProcStat reads the /proc/<pid>/stat file and parses it into a ProcStat struct.
func NewProcStat(pid int) (*ProcStat, error) {
	filePath := fmt.Sprintf("/proc/%v/stat", pid)
	return newProcStat(filePath)
}

func newProcStat(filePath string) (*ProcStat, error) {
	statBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// replace spaces in comm with 0x80 (so it can be parsed as a single field).
	// after parsing, if comm is required, fix it back to spaces.
	commStart := bytes.IndexByte(statBytes, '(')
	commEnd := bytes.LastIndexByte(statBytes, ')')
	if commStart == -1 || commEnd == -1 {
		return nil, fmt.Errorf("comm field not found in proc stat file")
	}
	for i := commStart; i <= commEnd; i++ {
		if statBytes[i] != ' ' {
			continue
		}
		statBytes[i] = 0x80 // out of ASCII range to avoid conflicts
	}

	statFields := bytes.Fields(statBytes)
	if len(statFields) != StatNumFields {
		return nil, fmt.Errorf("unexpected number of fields in proc stat file: %d", len(statFields))
	}

	remainingFields := len(procStatValueParserArray)
	stat := &ProcStat{}
	for i, parseValue := range procStatValueParserArray {
		if parseValue == nil {
			// skip fields that are not required, see procStatValueParserArray and ProcStat struct
			continue
		}

		parseValue(string(statFields[i]), stat)
		remainingFields--
		if remainingFields == 0 {
			break
		}
	}

	return stat, nil
}

// stat fields parsers

func parseStartTime(value string, s *ProcStat) {
	s.startTime = parseUint64(value)
}

//
// Public methods
//

// GetStartTime returns the time the process started after system boot (in clock ticks).
func (s *ProcStat) GetStartTime() uint64 {
	return s.startTime
}

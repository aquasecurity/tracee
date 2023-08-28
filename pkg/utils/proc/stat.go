package proc

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/aquasecurity/tracee/pkg/errfmt"
)

//
// ProcStat: /proc/[pid]/stat
//

type ProcStat struct {
	Pid                 int    // process id
	Comm                string // the filename of the executable
	State               byte   // process state
	Ppid                int    // parent process id
	Pgrp                int    // process group id
	Session             int    // session id
	TtyNr               int    // controlling terminal
	Tpgid               int    // foreground process group id of the controlling terminal
	Flags               uint   // process flags
	MinFlt              uint64 // number of minor faults
	CminFlt             uint64 // number of minor faults (all childs)
	MajFlt              uint64 // number of major faults
	CmajFlt             uint64 // number of major faults (all childs)
	Utime               int64  // user mode jiffies (clock ticks)
	Stime               int64  // kernel mode jiffies (clock ticks)
	Cutime              int64  // user mode jiffies (all childs)
	Cstime              int64  // kernel mode jiffies (all childs)
	Priority            int    // process priority
	Nice                int    // process nice value
	NumThreads          int    // number of threads in this process
	ItRealValue         int64  // (obsolete, always 0)
	StartTime           int64  // time the process started after system boot (in clock ticks)
	Vsize               int64  // virtual memory size
	Rss                 int64  // resident set memory size
	Rsslim              uint64 // current limit in bytes on the rss
	Startcode           int64  // address above which program text can run
	Endcode             int64  // address below which program text can run
	StartStack          int64  // address of the start of the main process stack
	Kstkesp             int64  // current value of stack pointer
	Kstkeip             int64  // current value of instruction pointer
	Signal              uint64 // bitmap of pending signals
	Blocked             uint64 // bitmap of blocked signals
	SigIgnore           uint64 // bitmap of ignored signals
	Sigcatch            uint64 // bitmap of catched signals
	Wchan               int64  // address of the syscall where process is in sleep mode
	Nswap               int64  // number of swapped pages
	Cnswap              int64  // cumulative nswap for child processes
	ExitSignal          int    // signal to be sent to parent when we die
	Processor           int    // current CPU
	RtPriority          int    // realtime priority
	Policy              int    // scheduling policy
	DelayacctBlkioTicks int64  // time spent waiting for block IO
	GuestTime           int64  // guest time of the process
	CguestTime          int64  // guest time of the process's children
	StartData           int64  // address above which program data+bss is placed
	EndData             int64  // address below which program data+bss is placed
	StartBrk            int64  // address above which program heap can be expanded with brk()
	ArgStart            int64  // address above which program command line is placed
	ArgEnd              int64  // address below which program command line is placed
	EnvStart            int64  // address above which program environment is placed
	EnvEnd              int64  // address below which program environment is placed
	ExitCode            int    // the thread's exit_code in the form reported by the waitpid system call
}

func NewThreadProcStat(pid, tid int) (*ProcStat, error) {
	filepath := fmt.Sprintf("/proc/%v/task/%v/stat", pid, tid)
	return newProcStat(filepath)
}

func NewProcStat(pid int) (*ProcStat, error) {
	filePath := fmt.Sprintf("/proc/%v/stat", pid)
	return newProcStat(filePath)
}

var newProcStatRegex = regexp.MustCompile(`\([^)]+\)`)

func newProcStat(filePath string) (*ProcStat, error) {
	statBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	statString := string(statBytes)

	// replace spaces in comm with dots (so sscanf can parse it)
	statString = newProcStatRegex.ReplaceAllStringFunc(statString,
		func(s string) string {
			return strings.ReplaceAll(s, " ", ".")
		},
	)

	var stat ProcStat
	_, err = fmt.Sscanf(statString,
		"%d %s %c %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d "+
			"%d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d",
		&stat.Pid, &stat.Comm, &stat.State, &stat.Ppid, &stat.Pgrp, &stat.Session, &stat.TtyNr,
		&stat.Tpgid, &stat.Flags, &stat.MinFlt, &stat.CminFlt, &stat.MajFlt, &stat.CmajFlt,
		&stat.Utime, &stat.Stime, &stat.Cutime, &stat.Cstime, &stat.Priority, &stat.Nice,
		&stat.NumThreads, &stat.ItRealValue, &stat.StartTime, &stat.Vsize, &stat.Rss, &stat.Rsslim,
		&stat.Startcode, &stat.Endcode, &stat.StartStack, &stat.Kstkesp, &stat.Kstkeip,
		&stat.Signal, &stat.Blocked, &stat.SigIgnore, &stat.Sigcatch, &stat.Wchan, &stat.Nswap,
		&stat.Cnswap, &stat.ExitSignal, &stat.Processor, &stat.RtPriority, &stat.Policy,
		&stat.DelayacctBlkioTicks, &stat.GuestTime, &stat.CguestTime, &stat.StartData,
		&stat.EndData, &stat.StartBrk, &stat.ArgStart, &stat.ArgEnd, &stat.EnvStart, &stat.EnvEnd,
		&stat.ExitCode)
	if err != nil {
		return nil, errfmt.Errorf("error parsing %v: %v", filePath, err)
	}

	return &stat, nil
}

package proc

import (
	"bytes"

	"github.com/aquasecurity/tracee/pkg/errfmt"
)

//
// ProcStat
// https://elixir.bootlin.com/linux/v6.13/source/fs/proc/array.c#L589
// https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html
//

type StatField byte

// Fields from /proc/<pid>/[task/<tid>/]stat file
const (
	// There are signedness discrepancies between the fmt and the kernel C type in some cases, e.g.:
	// - StatCutime, StatCstime and StatCguestTime are `int64` in fmt but `u64` in kernel C type.
	// - StatRss is `int64` in fmt but `unsigned long` in kernel C type.
	// To avoid confusion, the parse type is based on the fmt since it is the representation made
	// available in the stat file. A conversion to the actual kernel C type should be done after parsing.
	//
	// parse type:    type to be used to parse the field value.
	// fmt:           format specifier string specified in stat man page.
	// kernel C type: actual type of the field in the kernel.
	//
	//                                       // parse type  // fmt  // kernel C type      // description
	//                                       // ----------  // ---  // ------------------ // ----------------------------------------------------------------------
	StatPid                 StatField = iota // int32          %d      pid_t (int)           process id
	StatComm                                 // string         %s      char[64]              the name of the task - up to 64 + 2 for ()
	StatState                                // byte           %c      char                  process state
	StatPpid                                 // int32          %d      pid_t (int)           parent process id
	StatPgrp                                 // int32          %d      pid_t (int)           process group id
	StatSession                              // int32          %d      pid_t (int)           session id
	StatTtyNr                                // int32          %d      int                   controlling terminal
	StatTpgid                                // int32          %d      int                   foreground process group id of the controlling terminal
	StatFlags                                // uint32         %u      unsigned int          process flags
	StatMinFlt                               // uint64         %lu     unsigned long         number of minor faults
	StatCminFlt                              // uint64         %lu     unsigned long         number of minor faults (all childs)
	StatMajFlt                               // uint64         %lu     unsigned long         number of major faults
	StatCmajFlt                              // uint64         %lu     unsigned long         number of major faults (all childs)
	StatUtime                                // uint64         %lu     u64                   user mode jiffies (clock ticks)
	StatStime                                // uint64         %lu     u64                   kernel mode jiffies (clock ticks)
	StatCutime                               // int64          %ld     u64                   user mode jiffies (all childs)
	StatCstime                               // int64          %ld     u64                   kernel mode jiffies (all childs)
	StatPriority                             // int32          %ld     int                   process priority
	StatNice                                 // int32          %ld     int                   process nice value
	StatNumThreads                           // int32          %ld     int                   number of threads in this process
	StatItRealValue                          // always 0 (obsolete)
	StatStartTime                            // uint64         %llu    unsigned long long    time the process started after system boot (in clock ticks)
	StatVsize                                // uint64         %lu     unsigned long         virtual memory size
	StatRss                                  // int64          %ld     unsigned long         resident set memory size
	StatRsslim                               // uint64         %lu     unsigned long         current limit in bytes on the rss
	StatStartcode                            // uint64         %lu     unsigned long         address above which program text can run
	StatEndcode                              // uint64         %lu     unsigned long         address below which program text can run
	StatStartStack                           // uint64         %lu     unsigned long         address of the start of the main process stack
	StatKstkesp                              // uint64         %lu     unsigned long         current value of stack pointer
	StatKstkeip                              // uint64         %lu     unsigned long         current value of instruction pointer
	StatSignal                               // uint64         %lu     unsigned long         bitmap of pending signals
	StatBlocked                              // uint64         %lu     unsigned long         bitmap of blocked signals
	StatSigIgnore                            // uint64         %lu     unsigned long         bitmap of ignored signals
	StatSigcatch                             // uint64         %lu     unsigned long         bitmap of catched signals
	StatWchan                                // uint64         %lu     unsigned long         address of the syscall where process is in sleep mode
	StatNswap                                // always 0 (not maintained)
	StatCnswap                               // always 0 (not maintained)
	StatExitSignal                           // int32          %d      int                   signal to be sent to parent when we die
	StatProcessor                            // uint32         %d      unsigned int          current CPU
	StatRtPriority                           // uint32         %u      unsigned int          realtime priority
	StatPolicy                               // uint32         %u      unsigned int          scheduling policy
	StatDelayacctBlkioTicks                  // uint64         %llu    u64                   time spent waiting for block IO
	StatGuestTime                            // uint64         %lu     u64                   guest time of the process
	StatCguestTime                           // int64          %ld     u64                   guest time of the process's children
	StatStartData                            // uint64         %lu     unsigned long         address above which program data+bss is placed
	StatEndData                              // uint64         %lu     unsigned long         address below which program data+bss is placed
	StatStartBrk                             // uint64         %lu     unsigned long         address above which program heap can be expanded with brk()
	StatArgStart                             // uint64         %lu     unsigned long         address above which program command line is placed
	StatArgEnd                               // uint64         %lu     unsigned long         address below which program command line is placed
	StatEnvStart                             // uint64         %lu     unsigned long         address above which program environment is placed
	StatEnvEnd                               // uint64         %lu     unsigned long         address below which program environment is placed
	StatExitCode                             // int32          %d      int                   the thread's exit_code in the form reported by the waitpid system call
)

const (
	StatLastField                 = StatExitCode
	StatMaxNumFields              = StatLastField + 1
	StatReadFileInitialBufferSize = 256 // greater than average size (~95) calculated from ~1.4k stat files
)

// ProcStat represents the minimal required fields of the /proc stat file.
type ProcStat struct {
	startTime uint64 // StatStartTime
	// rss       uint64 // StatRss (parsed as int64)
}

type procStatValueParser func(value []byte, s *ProcStat)

// procStatValueParserArray maps the index of the field in the stat file to its respective value parser.
// If a parser is nil, the field is ignored on parsing.
var procStatValueParserArray = [StatMaxNumFields]procStatValueParser{
	StatStartTime: parseStartTime, // StartTime
}

// statDefaultFields is the default set of fields to parse from the stat file.
// It is used when no fields are specified.
// Even though a subset, they must be ordered as in the StatField enum to ensure correct parsing.
var statDefaultFields = []StatField{
	StatStartTime,
}

// NewThreadProcStat reads the /proc/<pid>/task/<tid>/stat file and parses it into a ProcStat struct.
// Populates all default fields.
func NewThreadProcStat(pid, tid int32) (*ProcStat, error) {
	taskStatPath := GetTaskStatPath(pid, tid)
	return newProcStat(taskStatPath, statDefaultFields)
}

// NewProcStat reads the /proc/<pid>/stat file and parses it into a ProcStat struct.
// Populates all default fields.
func NewProcStat(pid int32) (*ProcStat, error) {
	statPath := GetStatPath(pid)
	return newProcStat(statPath, statDefaultFields)
}

// NewThreadProcStatFields reads the /proc/<pid>/task/<tid>/stat file and parses it into a ProcStat struct.
// Populates only the specified fields.
func NewThreadProcStatFields(pid, tid int32, fields []StatField) (*ProcStat, error) {
	taskStatPath := GetTaskStatPath(pid, tid)
	return newProcStat(taskStatPath, fields)
}

// NewProcStatFields reads the /proc/<pid>/stat file and parses it into a ProcStat struct.
// Populates only the specified fields.
func NewProcStatFields(pid int32, fields []StatField) (*ProcStat, error) {
	statPath := GetStatPath(pid)
	return newProcStat(statPath, fields)
}

func newProcStat(filePath string, fields []StatField) (*ProcStat, error) {
	statBytes, err := ReadFile(filePath, StatReadFileInitialBufferSize)
	if err != nil {
		return nil, err
	}

	stat := &ProcStat{}
	err = stat.parse(statBytes, fields)
	if err != nil {
		return nil, err
	}

	return stat, nil
}

// parse parses the stat file for the required fields filling the ProcStat struct.
func (s *ProcStat) parse(statBytes []byte, fields []StatField) error {
	if len(statBytes) == 0 {
		return errfmt.Errorf("empty stat file")
	}
	if len(fields) == 0 {
		return errfmt.Errorf("none stat fields specified")
	}

	reqFieldIdx := 0
	statIdx := 0

	var parser procStatValueParser

	// handle `Pid` field if requested
	pidEnd := bytes.IndexByte(statBytes, ' ')
	if pidEnd == -1 {
		return errfmt.Errorf("pid field not found in proc stat file")
	}
	if reqFieldIdx < len(fields) && fields[reqFieldIdx] == StatPid {
		parser = procStatValueParserArray[StatPid]
		parser(statBytes[:pidEnd], s)
		reqFieldIdx++
	}
	statIdx = pidEnd + 1

	// handle `Comm` field if requested
	commEnd := bytes.LastIndexByte(statBytes[statIdx:], ')')
	if commEnd == -1 {
		return errfmt.Errorf("comm field not found in proc stat file")
	}
	if reqFieldIdx < len(fields) && fields[reqFieldIdx] == StatComm {
		commStart := bytes.IndexByte(statBytes[statIdx:], '(')
		if commStart == -1 {
			return errfmt.Errorf("comm field not found in proc stat file")
		}

		parser = procStatValueParserArray[StatComm]
		parser(statBytes[statIdx+commStart+1:statIdx+commEnd], s)
		reqFieldIdx++
	}
	statIdx += commEnd + 2

	// skip to and extract remaining required fields
	parsingFieldIdx := 2 // start after `Pid` (0) and `Comm` (1)
	for i := statIdx; i < len(statBytes) && reqFieldIdx < len(fields); {
		// find the next field boundary (space)
		fieldEnd := bytes.IndexByte(statBytes[i:], ' ')
		if fieldEnd == -1 {
			fieldEnd = len(statBytes)
		} else {
			fieldEnd += i
		}

		field := fields[reqFieldIdx]
		// check if the requested field matches the current parsing field
		if field == StatField(parsingFieldIdx) {
			if field == StatLastField {
				fieldEnd-- // trim the newline character
			}

			parser = procStatValueParserArray[field]
			parser(statBytes[i:fieldEnd], s)
			reqFieldIdx++
		}

		// move to the next field to parse
		parsingFieldIdx++
		i = fieldEnd + 1
	}

	if reqFieldIdx < len(fields) {
		return errfmt.Errorf("some requested fields were not found in the proc stat file")
	}

	return nil
}

// stat fields parsers

func parseStartTime(value []byte, s *ProcStat) {
	s.startTime, _ = ParseUint64(string(value))
}

// func parseRss(value []byte, s *ProcStat) {
// 	rss, _ := ParseInt64(string(value)) // parse as available in the stat file
// 	s.rss = uint64(rss)
// }

//
// Public methods
//

// GetStartTime returns the time the process started after system boot (in clock ticks).
func (s *ProcStat) GetStartTime() uint64 {
	return s.startTime
}

// // GetRss returns the resident set memory size.
// func (s *ProcStat) GetRss() uint64 {
// 	return s.rss
// }

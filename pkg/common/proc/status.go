package proc

import (
	"bytes"

	"github.com/aquasecurity/tracee/pkg/errfmt"
)

//
// ProcStatus
// https://elixir.bootlin.com/linux/v6.13/source/fs/proc/array.c#L444
// https://man7.org/linux/man-pages/man5/proc_pid_status.5.html
//

type StatusField byte

// Fields from /proc/<pid>/[task/<tid>/]status file:
const (
	//                        // parse type  // fmt  // kernel C type            // description
	//                        // ----------  // ---  // ----------------------   // ----------------------------------------------------------------------
	Name StatusField = iota // string         %s      char[64]                 // Name of the process
	// if umask >= 0
	Umask //                     int32          %#04o   int                      // Process umask, expressed in octal with a leading zero
	// endif umask >= 0
	//
	State     //                 byte           %c      char                     // State of the process (leftmost char of the field)
	Tgid      //                 uint64         %llu    pid_t (int)              // Thread group ID
	Ngid      //                 uint64         %llu    pid_t (int)              // NUMA group ID (if available)
	Pid       //                 uint64         %llu    pid_t (int)              // Process ID
	PPid      //                 uint64         %llu    pid_t (int)              // Parent Process ID
	TracerPid //                 uint64         %llu    pid_t (int)              // PID of process tracing this process
	Uid
	// (separator is '\t')
	// UidReal                   uint64         %llu    uid_t (unsigned int)     // Real UID
	// UidEffective              uint64         %llu    uid_t (unsigned int)     // Effective UID
	// UidSaved                  uint64         %llu    uid_t (unsigned int)     // Saved set UID
	// UidFS                     uint64         %llu    uid_t (unsigned int)     // Filesystem UID
	Gid
	// (separator is '\t')
	// GidReal                   uint64         %llu    gid_t (unsigned int)     // Real GID
	// GidEffective              uint64         %llu    gid_t (unsigned int)     // Effective GID
	// GidSaved                  uint64         %llu    gid_t (unsigned int)     // Saved set GID
	// GidFS                     uint64         %llu    gid_t (unsigned int)     // Filesystem GID
	FDSize //                    uint64         %llu    unsigned int             // Number of file descriptor slots currently allocated
	Groups //                    []uint64       %llu    gid_t (unsigned int)     // Supplementary group list (separator is ' ')
	//
	// #ifdef CONFIG_PID_NS
	NStgid  //                   []uint64       %llu    pid_t (int)              // Thread group ID in each of the PID namespaces of which pid is a member
	NSpid   //                   []uint64       %llu    pid_t (int)              // Thread ID in each of the PID namespaces of which pid is a member
	NSpgid  //                   []uint64       %llu    pid_t (int)              // Process group ID in each of the PID namespaces of which pid is a member
	NSsid   //                   []uint64       %llu    pid_t (int)              // Namespace session ID in each of the PID namespaces of which pid is a member
	Kthread //                   bool           %c      char                     // Is the process a kernel thread? (0 = no, 1 = yes)
	// #endif // CONFIG_PID_NS
	//
	// if mm != NULL
	VmPeak       //              uint64         %8llu   unsigned long            // Peak virtual memory size (kB)
	VmSize       //              uint64         %8llu   unsigned long            // Total program size (kB)
	VmLck        //              uint64         %8llu   unsigned long            // Locked memory size (kB)
	VmPin        //              uint64         %8llu   s64                      // Pinned memory size (guaranteed never to be swapped out) (kB)
	VmHWM        //              uint64         %8llu   unsigned long            // Peak resident set size ("high water mark") (kB)
	VmRSS        //              uint64         %8llu   unsigned long            // Resident set size (kB)
	RssAnon      //              uint64         %8llu   unsigned long            // Size of resident anonymous memory (kB)
	RssFile      //              uint64         %8llu   unsigned long            // Size of resident file mappings (kB)
	RssShmem     //              uint64         %8llu   unsigned long            // Size of shared memory resident (kB)
	VmData       //              uint64         %8llu   unsigned long            // Size of data segment (kB)
	VmStk        //              uint64         %8llu   unsigned long            // Size of stack segment (kB)
	VmExe        //              uint64         %8llu   unsigned long            // Size of text segment (kB)
	VmLib        //              uint64         %8llu   unsigned long            // Shared library code size (kB)
	VmPTE        //              uint64         %8llu   unsigned long            // Page table entries size (kB)
	VmSwap       //              uint64         %8llu   unsigned long            // Swap size (kB)
	HugetlbPages //              uint64         %8lu    long                     // Size of hugetlb memory portions (kB)
	// endif mm != NULL
	//
	CoreDumping //               bool           %llu    int                      // Is the process dumping core? (0 = no, 1 = yes)
	THPEnabled  //               bool           %d      bool                     // Is transparent huge pages enabled? (0 = no, 1 = yes)
	UntagMask   //               uint64         %#lx    unsigned long            // Untag mask
	Threads     //               uint64         %llu    int                      // Number of threads in process containing this thread
	SigQ
	// (separator is '/')
	// SigQ                      uint64         %llu    unsigned int             // Number of signals queued for the thread
	// SigQLimit                 uint64         %llu    unsigned long            // Resource limit on number of signals that can be queued
	SigPnd //                    uint64         %016llx sigset_t (unsigned long) // Mask of signals pending for the thread
	ShdPnd //                    uint64         %016llx sigset_t (unsigned long) // Mask of signals that thread is sharing
	SigBlk //                    uint64         %016llx sigset_t (unsigned long) // Mask of signals being blocked
	SigIgn //                    uint64         %016llx sigset_t (unsigned long) // Mask of signals being ignored
	SigCgt //                    uint64         %016llx sigset_t (unsigned long) // Mask of signals being caught
	//
	CapInh     //                uint64         %016llx cap_user_header_t (u64)  // Mask of inheritable capabilities
	CapPrm     //                uint64         %016llx cap_user_header_t (u64)  // Mask of permitted capabilities
	CapEff     //                uint64         %016llx cap_user_header_t (u64)  // Mask of effective capabilities
	CapBnd     //                uint64         %016llx cap_user_header_t (u64)  // Mask of capabilities bounding set
	CapAmb     //                uint64         %016llx cap_user_header_t (u64)  // Ambient capability set
	NoNewPrivs //                bool           %d      bool                     // Was the process started with no new privileges? (0 = no, 1 = yes)
	//
	// #ifdef CONFIG_SECCOMP
	Seccomp //                   uint64         %llu    int                      // Seccomp mode of the process
	// #endif // CONFIG_SECCOMP
	//
	// #ifdef CONFIG_SECCOMP_FILTER
	Seccomp_filters //           uint64         %llu    int                      // Number of seccomp filters attached to the process
	// #endif // CONFIG_SECCOMP_FILTER
	//
	SpeculationStoreBypass    // string         %s      char *                   // Speculation flaw mitigation state
	SpeculationIndirectBranch // string         %s      char *                   // Speculation indirect branch mitigation state
	//
	CpusAllowed     //           uint64         %016llx unsigned long            // Mask of CPUs on which this process may run
	CpusAllowedList //           string         %s      char *                   // Same as previous, but in "list format" (e.g. "0-3,5,7")
	//
	MemsAllowed     //           uint64         %016llx unsigned long            // Mask of memory nodes allowed to this process
	MemsAllowedList //           string         %s      char *                   // Same as previous, but in "list format" (e.g. "0-3,5,7")
	//
	VoluntaryCtxtSwitches    //  uint64         %llu    unsigned long            // Number of voluntary context switches
	NonVoluntaryCtxtSwitches //  uint64         %llu    unsigned long            // Number of involuntary context switches
	//
	// #ifdef CONFIG_X86_USER_SHADOW_STACK
	x86ThreadFeatures       //   string         %s      char *                   // x86 Thread features
	x86ThreadFeaturesLocked //   string         %s      char *                   // x86 Thread features locked
	// #endif // CONFIG_X86_USER_SHADOW_STACK
	//
)

const (
	StatusLastField                 = x86ThreadFeaturesLocked
	StatusMaxNumFields              = StatusLastField + 1
	StatusReadFileInitialBufferSize = 1480 // greater than average size (~1290) calculated from ~700 status files
)

// ProcStatus represents the minimal required fields of the /proc status file.
type ProcStatus struct {
	name   string // up to 64 chars: https://elixir.bootlin.com/linux/v6.13/source/fs/proc/array.c#L101
	tgid   int32
	pid    int32
	pPid   int32
	nstgid int32
	nspid  int32
	nspgid int32
}

type procStatusParser struct {
	fieldName []byte
	parse     func(value []byte, s *ProcStatus)
}

// procStatusValueParserArray maps the indexes of the status lines (fields) to their respective value parsers.
var procStatusValueParserArray = [StatusMaxNumFields]procStatusParser{
	Name:   {fieldName: []byte("Name"), parse: parseName},
	Tgid:   {fieldName: []byte("Tgid"), parse: parseTgid},
	Pid:    {fieldName: []byte("Pid"), parse: parsePid},
	PPid:   {fieldName: []byte("PPid"), parse: parsePPid},
	NStgid: {fieldName: []byte("NStgid"), parse: parseNsTgid},
	NSpid:  {fieldName: []byte("NSpid"), parse: parseNsPid},
	NSpgid: {fieldName: []byte("NSpgid"), parse: parseNsPgid},
}

// statusDefaultFields is the default set of fields to parse from the status file.
// It is used when no fields are specified.
// Even though a subset, they must be ordered as in the StatusField enum to ensure correct parsing.
var statusDefaultFields = []StatusField{
	Name,
	Tgid,
	Pid,
	PPid,
	NStgid,
	NSpid,
	NSpgid,
}

// NewThreadProcStatus reads the /proc/<pid>/task/<tid>/status file and parses it into a ProcStatus struct.
// Populates all default fields.
func NewThreadProcStatus(pid, tid int32) (*ProcStatus, error) {
	taskStatusPath := GetTaskStatusPath(pid, tid)
	return newProcStatus(taskStatusPath, statusDefaultFields)
}

// NewProcStatus reads the /proc/<pid>/status file and parses it into a ProcStatus struct.
// Populates all default fields.
func NewProcStatus(pid int32) (*ProcStatus, error) {
	statusPath := GetStatusPath(pid)
	return newProcStatus(statusPath, statusDefaultFields)
}

// NewThreadProcStatusFields reads the /proc/<pid>/task/<tid>/status file and parses it into a ProcStatus struct.
// Populates only the specified fields.
func NewThreadProcStatusFields(pid, tid int32, fields []StatusField) (*ProcStatus, error) {
	taskStatusPath := GetTaskStatusPath(pid, tid)
	return newProcStatus(taskStatusPath, fields)
}

// NewProcStatusFields reads the /proc/<pid>/status file and parses it into a ProcStatus struct.
// Populates only the specified fields.
func NewProcStatusFields(pid int32, fields []StatusField) (*ProcStatus, error) {
	statusPath := GetStatusPath(pid)
	return newProcStatus(statusPath, fields)
}

func newProcStatus(filePath string, fields []StatusField) (*ProcStatus, error) {
	statusBytes, err := ReadFile(filePath, StatusReadFileInitialBufferSize)
	if err != nil {
		return nil, err
	}

	status := &ProcStatus{}
	err = status.parse(statusBytes, fields)
	if err != nil {
		return nil, err
	}

	return status, nil
}

// parse parses the status file for the required fields filling the ProcStatus struct.
func (s *ProcStatus) parse(statusBytes []byte, fields []StatusField) error {
	if len(statusBytes) == 0 {
		return errfmt.Errorf("empty status file")
	}
	if len(fields) == 0 {
		return errfmt.Errorf("none status fields specified")
	}

	fieldsNeeded := len(fields)

	// single-pass parsing of the status file
	pos := 0
	for pos < len(statusBytes) && fieldsNeeded > 0 {
		// find end of the current line
		end := bytes.IndexByte(statusBytes[pos:], '\n')
		if end == -1 {
			end = len(statusBytes)
		} else {
			end += pos
		}

		line := statusBytes[pos:end]
		field := fields[len(fields)-fieldsNeeded]
		parser := procStatusValueParserArray[field]

		if !bytes.HasPrefix(line, parser.fieldName) {
			pos = end + 1 // move to the beginning of the next line
			continue
		}

		// field found, parse the value

		// find the first non-space/tab character after the colon
		valueStart := len(parser.fieldName) + 1
		for i := valueStart; i < len(line); i++ {
			if line[i] != ' ' && line[i] != '\t' {
				valueStart = i
				break
			}
		}

		value := line[valueStart:]
		parser.parse(value, s)
		fieldsNeeded--
	}

	if fieldsNeeded > 0 {
		return errfmt.Errorf("failed to parse all required fields from status file")
	}

	return nil
}

// status fields parsers

func parseName(value []byte, s *ProcStatus) {
	s.name = string(value)
}

func parseTgid(value []byte, s *ProcStatus) {
	s.tgid, _ = ParseInt32(string(value))
}

func parsePid(value []byte, s *ProcStatus) {
	s.pid, _ = ParseInt32(string(value))
}

func parsePPid(value []byte, s *ProcStatus) {
	s.pPid, _ = ParseInt32(string(value))
}

func parseNsTgid(value []byte, s *ProcStatus) {
	s.nstgid, _ = ParseInt32(string(value))
}

func parseNsPid(value []byte, s *ProcStatus) {
	s.nspid, _ = ParseInt32(string(value))
}

func parseNsPgid(value []byte, s *ProcStatus) {
	s.nspgid, _ = ParseInt32(string(value))
}

//
// Public methods
//

// GetName returns the name of the process.
func (s *ProcStatus) GetName() string {
	return s.name
}

// GetPid returns the process ID.
func (s *ProcStatus) GetPid() int32 {
	return s.pid
}

// GetTgid returns the thread group ID.
func (s *ProcStatus) GetTgid() int32 {
	return s.tgid
}

// GetPPid returns the parent process ID.
func (s *ProcStatus) GetPPid() int32 {
	return s.pPid
}

// GetNsPid returns process ID in the namespace of the process.
func (s *ProcStatus) GetNsPid() int32 {
	return s.nspid
}

// GetNsTgid returns thread group ID in the namespace of the process.
func (s *ProcStatus) GetNsTgid() int32 {
	return s.nstgid
}

// GetNsPPid returns process group ID in the namespace of the process.
func (s *ProcStatus) GetNsPPid() int32 {
	return s.nspgid
}

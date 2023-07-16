package datasource

import "time"

// ProcessInfo is the user facing representation of a process data at a specific time.
type ProcessInfo struct {
	Pid               int
	NsPid             int
	Ppid              int
	UserId            int
	ContainerId       string
	Cmd               []string
	ExecutionBinary   FileInfo
	StartTime         time.Time // First thread fork time. TODO: Can we use the main thread start time instead?
	ExecTime          time.Time // Last execve call time
	ExitTime          time.Time
	ThreadsIds        []int
	ChildProcessesIds []int
	IsAlive           bool
}

// ThreadInfo is the user facing representation of a thread data at a specific time.
type ThreadInfo struct {
	Tid        int
	NsTid      int
	Pid        int
	ForkTime   time.Time
	ExitTime   time.Time
	Namespaces NamespacesIds
	Name       string
	IsAlive    bool
}

type FileInfo struct {
	Path   string
	Hash   string // TODO: should we call it SHA256 or Hash?
	Inode  uint
	Device uint
	Ctime  time.Time
}

type NamespacesIds struct {
	// TODO: Support all namespaces
	Pid   int
	Mount int
}

// ProcessLineage is a representation of a process and its ancestors until the oldest ancestor
// known in the tree.
// The lineage is only relevant for the container the process resides in.
type ProcessLineage []ProcessInfo

// ProcKey is a key to the process tree data source, which will result receiving ProcessInfo in the
// response for the matching process in the given time.
type ProcKey struct {
	Pid  int
	Time time.Time
}

// ThreadKey is a key to the process tree data source, which will result receiving ThreadInfo in the
// response for the matching thread in the given time.
type ThreadKey struct {
	Tid  int
	Time time.Time
}

// LineageKey is a key to the process tree data source, which will result receiving ProcessLineage in the
// response for the matching process in the given time, up to the max depth given of ancestors.
type LineageKey struct {
	Pid      int
	Time     time.Time
	MaxDepth int
}

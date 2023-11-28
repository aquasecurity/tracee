package datasource

import (
	"time"
)

// TimeRelevantInfo is the returned value of all the time specific process tree queries.
// It envelopes the information from the tree with the time it is relevant for.
type TimeRelevantInfo[T any] struct {
	Timestamp time.Time
	Info      T
}

// ProcessInfo is the user facing representation of a process data at a specific time.
type ProcessInfo struct {
	EntityId          uint32
	Pid               int
	NsPid             int
	Ppid              int
	ContainerId       string
	Cmd               []string
	ExecutionBinary   FileInfo
	Interpreter       FileInfo
	Interp            FileInfo
	StartTime         time.Time // First thread fork time
	ExecTime          time.Time // Last execve call time
	ExitTime          time.Time
	ParentEntityId    uint32         // Parent process entity ID
	ThreadsIds        map[int]uint32 // Map between the tids to their entity IDs
	ChildProcessesIds map[int]uint32 // Map between the pids to their entity IDs
	IsAlive           bool
}

// ThreadInfo is the user facing representation of a thread data at a specific time.
type ThreadInfo struct {
	EntityId        uint32
	Tid             int
	NsTid           int
	Pid             int
	UserId          int
	GroupId         int
	StartTime       time.Time
	ExitTime        time.Time
	Name            string
	ProcessEntityId uint32
	IsAlive         bool
}

type FileInfo struct {
	Path   string
	Hash   string
	Inode  int
	Device int
	Ctime  time.Time
	Mode   int
}

// ProcessLineage is a representation of a process and its ancestors until the oldest ancestor
// known in the tree.
// The lineage is only relevant for the container the process resides in.
type ProcessLineage []TimeRelevantInfo[ProcessInfo]

// ProcKey is a key to the process tree data source, which will result receiving ProcessInfo in the
// response for the matching process in the given time.
type ProcKey struct {
	EntityId uint32 // The process's entity ID
	Time     time.Time
}

// ThreadKey is a key to the process tree data source, which will result receiving ThreadInfo in the
// response for the matching thread in the given time.
type ThreadKey struct {
	EntityId uint32 // The thread's entity ID
	Time     time.Time
}

// LineageKey is a key to the process tree data source, which will result receiving ProcessLineage in the
// response for the matching process in the given time, up to the max depth given of ancestors.
type LineageKey struct {
	EntityId uint32 // The first process (last descendant) entity ID
	Time     time.Time
	MaxDepth int
}

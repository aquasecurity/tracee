package datasource

import (
	"errors"
	"fmt"
	"time"

	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
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

// ProcessTreeDS is an envelope to the process tree datasource API, to make it intuitive and easy
// to use.
type ProcessTreeDS struct {
	ds detect.DataSource
}

// InitProcessTreeDS init a datasource envelopment instance with the process tree datasource.
func InitProcessTreeDS(ds detect.DataSource) *ProcessTreeDS {
	return &ProcessTreeDS{ds: ds}
}

// GetProcessTreeDataSource init a datasource envelopment instance using the context all signatures
// are initialized with.
// This is the recommended way to initialize an instance, as it simpler to use.
func GetProcessTreeDataSource(ctx detect.SignatureContext) (*ProcessTreeDS, error) {
	processTreeDataSource, ok := ctx.GetDataSource("tracee", "process_tree")
	if !ok {
		return nil, errors.New("data source tracee/process_tree is not registered")
	}

	if processTreeDataSource.Version() > 1 {
		return nil, fmt.Errorf(
			"data source tracee/process_tree version %d is not supported",
			processTreeDataSource.Version(),
		)
	}

	return InitProcessTreeDS(processTreeDataSource), nil
}

// GetThreadInfo query the datasource for the information of a specific thread.
func (ptds *ProcessTreeDS) GetThreadInfo(threadKey ThreadKey) (
	*TimeRelevantInfo[ThreadInfo], error,
) {
	threadQueryAnswer, err := ptds.ds.Get(threadKey)
	if err != nil {
		return nil, fmt.Errorf("could not find thread for thread %d", threadKey.EntityId)
	}
	threadInfo, ok := threadQueryAnswer["thread_info"].(TimeRelevantInfo[ThreadInfo])
	if !ok {
		return nil, fmt.Errorf("could not extract info of thread %d", threadKey.EntityId)
	}
	return &threadInfo, nil
}

// GetEventThreadInfo get the information of the thread emitting the current event
func (ptds *ProcessTreeDS) GetEventThreadInfo(eventObj *trace.Event) (
	*TimeRelevantInfo[ThreadInfo], error,
) {
	queryKey := ThreadKey{
		EntityId: eventObj.ThreadEntityId,
		Time:     time.Unix(0, int64(eventObj.Timestamp)), // at the time event was emitted
	}
	return ptds.GetThreadInfo(queryKey)
}

// GetProcessInfo query the datasource for the information of a specific process.
func (ptds *ProcessTreeDS) GetProcessInfo(processKey ProcKey) (
	*TimeRelevantInfo[ProcessInfo], error,
) {
	// Pick the process info from the data source
	procQueryAnswer, err := ptds.ds.Get(processKey)
	if err != nil {
		return nil, fmt.Errorf("could not find process for process %d", processKey.EntityId)
	}
	procInfo, ok := procQueryAnswer["process_info"].(TimeRelevantInfo[ProcessInfo])
	if !ok {
		return nil, fmt.Errorf("could not extract info of process %d", processKey.EntityId)
	}
	return &procInfo, nil
}

// GetEventProcessInfo get the information of the process emitting the current event
func (ptds *ProcessTreeDS) GetEventProcessInfo(eventObj *trace.Event) (
	*TimeRelevantInfo[ProcessInfo], error,
) {
	queryKey := ProcKey{
		EntityId: eventObj.ProcessEntityId,
		Time:     time.Unix(0, int64(eventObj.Timestamp)), // at the time event was emitted
	}
	return ptds.GetProcessInfo(queryKey)
}

// GetProcessLineage query the datasource for the information of the process lineage of a
// specific process.
func (ptds *ProcessTreeDS) GetProcessLineage(lineageKey LineageKey) (
	*ProcessLineage, error,
) {
	// Pick the lineage info from the data source.
	lineageQueryAnswer, err := ptds.ds.Get(lineageKey)
	if err != nil {
		return nil, fmt.Errorf("could not find thread of process %d", lineageKey.EntityId)
	}
	lineageInfo, ok := lineageQueryAnswer["process_lineage"].(ProcessLineage)
	if !ok {
		return nil, fmt.Errorf("could not extract info of process %d", lineageKey.EntityId)
	}
	return &lineageInfo, nil
}

// GetEventProcessLineage get the process lineage information of the process emitting the
// current event.
func (ptds *ProcessTreeDS) GetEventProcessLineage(
	eventObj *trace.Event,
	maxDepth int,
) (*ProcessLineage, error) {
	queryKey := LineageKey{
		EntityId: eventObj.ProcessEntityId,
		Time:     time.Unix(0, int64(eventObj.Timestamp)), // at the time event was emitted
		MaxDepth: maxDepth,
	}
	return ptds.GetProcessLineage(queryKey)
}

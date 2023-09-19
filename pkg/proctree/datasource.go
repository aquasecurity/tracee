package proctree

import (
	"encoding/json"
	"time"

	"github.com/aquasecurity/tracee/types/datasource"
	"github.com/aquasecurity/tracee/types/detect"
)

// DataSource is an implementation to detect.Datasource interface, enveloping the ProcessTree type.
// It exposes all the relevant information of the tree using the interface methods.
type DataSource struct {
	procTree *ProcessTree
}

func NewDataSource(processTree *ProcessTree) *DataSource {
	return &DataSource{procTree: processTree}
}

func (ptds *DataSource) Get(key interface{}) (map[string]interface{}, error) {
	switch typedKey := key.(type) {
	case datasource.ProcKey:
		process, found := ptds.procTree.GetProcessByHash(typedKey.EntityId)
		if !found {
			return nil, detect.ErrDataNotFound
		}
		return map[string]interface{}{
			"process_info": ptds.exportProcessInfo(process, typedKey.Time),
		}, nil
	case datasource.ThreadKey:
		thread, found := ptds.procTree.GetThreadByHash(typedKey.EntityId)
		if !found {
			return nil, detect.ErrDataNotFound
		}
		return map[string]interface{}{
			"thread_info": ptds.exportThreadInfo(thread, typedKey.Time),
		}, nil
	case datasource.LineageKey:
		process, found := ptds.procTree.GetProcessByHash(typedKey.EntityId)
		if !found {
			return nil, detect.ErrDataNotFound
		}
		return map[string]interface{}{
			"process_lineage": ptds.exportProcessLineage(process, typedKey.Time, typedKey.MaxDepth),
		}, nil
	default:
		return nil, detect.ErrKeyNotSupported
	}
}

func (ptds *DataSource) Keys() []string {
	return []string{"datasource.ProcKey", "datasource.ThreadKey", "datasource.LineageKey"}
}

func (ptds *DataSource) Schema() string {
	schemaMap := map[string]string{
		"process_info":    "datasource.ProcessInfo",
		"thread_info":     "datasource.ThreadInfo",
		"process_lineage": "datasource.ProcessLineage",
	}
	schema, _ := json.Marshal(schemaMap)
	return string(schema)
}

func (ptds *DataSource) Version() uint {
	return 1 // TODO: Change to semantic versioning
}

func (ptds *DataSource) Namespace() string {
	return "tracee"
}

func (ptds *DataSource) ID() string {
	return "process_tree"
}

// exportProcessInfo return a representation of the given Process information relevant to given time
// as the expected datasource process structure.
func (ptds *DataSource) exportProcessInfo(
	process *Process,
	queryTime time.Time,
) datasource.ProcessInfo {
	info := process.GetInfo()
	executable := process.GetExecutable()
	interpreter := process.GetInterpreter()
	interp := process.GetInterp()

	existingChildren := make(map[int]uint32)
	for _, childHash := range process.GetChildren() {
		child, ok := ptds.procTree.GetProcessByHash(childHash)
		if !ok {
			continue
		}
		childInfo := child.GetInfo()
		if childInfo.IsAliveAt(queryTime) {
			existingChildren[childInfo.GetPid()] = childHash
		}
	}

	existingThreads := make(map[int]uint32)
	for _, threadHash := range process.GetThreads() {
		thread, ok := ptds.procTree.GetThreadByHash(threadHash)
		if !ok {
			continue
		}
		threadInfo := thread.GetInfo()
		if threadInfo.IsAliveAt(queryTime) {
			existingThreads[threadInfo.GetPid()] = threadHash
		}
	}

	infoFeed := info.GetFeedAt(queryTime)

	return datasource.ProcessInfo{
		EntityId:          process.GetHash(),
		Pid:               infoFeed.Pid,
		NsPid:             infoFeed.NsPid,
		Ppid:              infoFeed.PPid,
		ContainerId:       "",         // TODO: Add
		Cmd:               []string{}, // TODO: Add
		ExecutionBinary:   exportFileInfo(executable, queryTime),
		Interpreter:       exportFileInfo(interpreter, queryTime),
		Interp:            exportFileInfo(interp, queryTime),
		StartTime:         info.GetStartTime(),
		ExecTime:          time.Unix(0, 0), // TODO: Add
		ExitTime:          info.GetExitTime(),
		ParentEntityId:    process.GetParentHash(),
		ThreadsIds:        existingThreads,
		ChildProcessesIds: existingChildren,
		IsAlive:           info.IsAliveAt(queryTime),
	}
}

// exportThreadInfo return a representation of the given Thread information relevant to given time
// as the expected datasource thread structure.
func (ptds *DataSource) exportThreadInfo(
	thread *Thread,
	queryTime time.Time,
) datasource.ThreadInfo {
	info := thread.GetInfo()
	infoFeed := info.GetFeedAt(queryTime)
	return datasource.ThreadInfo{
		EntityId:  thread.GetHash(),
		Tid:       infoFeed.Tid,
		NsTid:     infoFeed.NsTid,
		Pid:       infoFeed.Pid,
		UserId:    infoFeed.Uid,
		GroupId:   infoFeed.Gid,
		StartTime: info.GetStartTime(),
		ExitTime:  info.GetExitTime(),
		Name:      infoFeed.Name,
		IsAlive:   info.IsAliveAt(queryTime),
	}
}

// exportProcessLineage return a representation of the given Process information and up to a given
// depth of its ancestors as the expected datasource process lineage structure.
// The information of each struct is relevant to the fork time of its dependent from it.
func (ptds *DataSource) exportProcessLineage(
	process *Process,
	queryTime time.Time,
	maxDepth int,
) datasource.ProcessLineage {
	lineage := datasource.ProcessLineage{
		ptds.exportProcessInfo(process, queryTime),
	}
	currentProcess := process
	var found bool
	var iterationQueryTime time.Time
	for depth := 0; depth < maxDepth; depth++ {
		// We don't want to get parents processes which are not part of the container.
		if currentProcess.GetInfo().GetNsPid() == 1 {
			break
		}
		iterationQueryTime = currentProcess.GetInfo().GetStartTime()
		currentProcess, found = ptds.procTree.GetProcessByHash(currentProcess.GetParentHash())
		if !found {
			break
		}
		lineage = append(lineage, ptds.exportProcessInfo(currentProcess, iterationQueryTime))
	}
	return lineage
}

// exportFileInfo return a representation of the given FileInfo information relevant to given time
// as the expected datasource file info structure.
func exportFileInfo(fileInfo *FileInfo, queryTime time.Time) datasource.FileInfo {
	fileInfoFeed := fileInfo.GetFeedAt(queryTime)
	return datasource.FileInfo{
		Path:   fileInfoFeed.Path,
		Hash:   "", // TODO: Add
		Inode:  fileInfoFeed.Inode,
		Device: fileInfoFeed.Dev,
		Ctime:  time.Unix(0, int64(fileInfoFeed.Ctime)),
		Mode:   fileInfoFeed.InodeMode,
	}
}

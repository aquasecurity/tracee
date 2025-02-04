package proctree

import (
	"encoding/json"
	"time"

	"github.com/aquasecurity/tracee/types/datasource"
	"github.com/aquasecurity/tracee/types/detect"
)

// DataSource is an implementation to detect.Datasource interface, enveloping the ProcessTree type.
type DataSource struct {
	procTree *ProcessTree
}

func NewDataSource(processTree *ProcessTree) *DataSource {
	return &DataSource{procTree: processTree}
}

// Keys returns a list of supported keys by the DataSource.
func (ptds *DataSource) Keys() []string {
	return []string{"datasource.ProcKey", "datasource.ThreadKey", "datasource.LineageKey"}
}

// Schema returns the schema of the DataSource.
func (ptds *DataSource) Schema() string {
	schemaMap := map[string]string{
		"process_info":    "datasource.TimeRelevantInfo[datasource.ProcessInfo]",
		"thread_info":     "datasource.TimeRelevantInfo[datasource.ThreadInfo]",
		"process_lineage": "datasource.TimeRelevantInfo[datasource.ProcessLineage]",
	}
	schema, _ := json.Marshal(schemaMap)
	return string(schema)
}

// Version returns the version of the DataSource.
func (ptds *DataSource) Version() uint {
	return 1 // TODO: Change to semantic versioning
}

// Namespace returns the namespace of the DataSource.
func (ptds *DataSource) Namespace() string {
	return "tracee"
}

// ID returns the ID of the DataSource.
func (ptds *DataSource) ID() string {
	return "process_tree"
}

// Get retrieves information from DataSource based on the provided key.
// It supports keys of the following types:
//
// - datasource.ProcKey (for process information retrieval)
// - datasource.ThreadKey (for thread information retrieval)
// - datasource.LineageKey (for process lineage information retrieval)
//
// and returns an error if the data isn't found.
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
	}
	return nil, detect.ErrKeyNotSupported
}

// exportProcessInfo returns information of the given Process at the given query time.
func (ptds *DataSource) exportProcessInfo(
	process *Process, queryTime time.Time,
) datasource.TimeRelevantInfo[datasource.ProcessInfo] {
	// Pick the objects related to the process from the process tree.
	info := process.GetInfo()
	procHash := process.GetHash()
	executable := process.GetExecutable()

	// Walk children hashes and discover the ones alive at the query time.
	aliveChildren := make(map[int]uint32)
	for _, childHash := range ptds.procTree.GetChildren(procHash) {
		child, ok := ptds.procTree.GetProcessByHash(childHash)
		if !ok {
			continue
		}
		childInfo := child.GetInfo()
		if childInfo.IsAliveAt(queryTime) {
			aliveChildren[int(childInfo.GetPid())] = childHash // TODO: change types pkg to reduce mem footprint
		}
	}

	// Walk thread hashes and discover the ones alive at the query time.
	aliveThreads := make(map[int]uint32)
	for _, threadHash := range ptds.procTree.GetThreads(procHash) {
		thread, ok := ptds.procTree.GetThreadByHash(threadHash)
		if !ok {
			continue
		}
		threadInfo := thread.GetInfo()
		if threadInfo.IsAliveAt(queryTime) {
			aliveThreads[int(threadInfo.GetTid())] = threadHash // TODO: change types pkg to reduce mem footprint
		}
	}

	// Pick the process information from the process tree.
	infoFeed := info.GetFeedAt(queryTime)

	// Export the information as the expected datasource process structure.
	return datasource.TimeRelevantInfo[datasource.ProcessInfo]{
		Info: datasource.ProcessInfo{
			EntityId: procHash,
			// TODO: change types pkg to reduce mem footprint (Pid, NsPid, Ppid, ThreadsIds, ChildProcessesIds)
			Pid:               int(infoFeed.Pid),
			NsPid:             int(infoFeed.NsPid),
			Ppid:              int(infoFeed.PPid),
			ContainerId:       "",         // TODO: Add
			Cmd:               []string{}, // TODO: Add
			ExecutionBinary:   exportFileInfo(executable, queryTime),
			StartTime:         info.GetStartTime(),
			ExecTime:          time.Unix(0, 0), // TODO: Add
			ExitTime:          info.GetExitTime(),
			ParentEntityId:    process.GetParentHash(),
			ThreadsIds:        aliveThreads,
			ChildProcessesIds: aliveChildren,
			IsAlive:           info.IsAliveAt(queryTime),
		},
		Timestamp: queryTime,
	}
}

// exportThreadInfo returns information of the given Thread at the given query time.
func (ptds *DataSource) exportThreadInfo(
	thread *Thread, queryTime time.Time,
) datasource.TimeRelevantInfo[datasource.ThreadInfo] {
	// Pick the objects related to the thread from the process tree.
	info := thread.GetInfo()
	infoFeed := info.GetFeedAt(queryTime)

	// Export the information as the expected datasource thread structure.
	return datasource.TimeRelevantInfo[datasource.ThreadInfo]{
		Info: datasource.ThreadInfo{
			EntityId: thread.GetHash(),
			// TODO: change types pkg to reduce mem footprint (Tid, NsTid, Pid, UserId, GroupId)
			Tid:       int(infoFeed.Tid),
			NsTid:     int(infoFeed.NsTid),
			Pid:       int(infoFeed.Pid),
			UserId:    int(infoFeed.Uid),
			GroupId:   int(infoFeed.Gid),
			StartTime: info.GetStartTime(),
			ExitTime:  info.GetExitTime(),
			Name:      infoFeed.Name,
			IsAlive:   info.IsAliveAt(queryTime),
		},
		Timestamp: queryTime,
	}
}

// exportProcessLineage returns the lineage of the given Process at the given query time. Lineage is
// a slice of process information, starting from the given process and going up to the max depth.
func (ptds *DataSource) exportProcessLineage(
	process *Process, queryTime time.Time, maxDepth int,
) datasource.ProcessLineage {
	var found bool
	var start time.Time
	var lineage datasource.ProcessLineage

	// Pick the process information from the process tree and add it to the lineage.
	lineage = append(lineage, ptds.exportProcessInfo(process, queryTime))

	// Walk the process tree up (parents) to the max depth.

	current := process
	for depth := 0; depth < maxDepth; depth++ {
		// If the current process is "init" stop the walk.
		if current.GetInfo().GetNsPid() == 1 {
			break
		}

		// Save the start time of the current process. The parent information
		// will be obtained at this time, the time the current process was
		// created, and not the query time.
		start = current.GetInfo().GetStartTime()

		// Get the parent process.
		current, found = ptds.procTree.GetProcessByHash(current.GetParentHash())
		if !found {
			break
		}

		// Add the parent process to the lineage.
		lineage = append(lineage, ptds.exportProcessInfo(current, start))
	}

	return lineage
}

// exportFileInfo returns information of the given FileInfo at the given query time.
func exportFileInfo(fileInfo *FileInfo, queryTime time.Time) datasource.FileInfo {
	// Pick the objects related to the file from the process tree.
	fileInfoFeed := fileInfo.GetFeedAt(queryTime)

	// Export the information as the expected datasource file structure.
	return datasource.FileInfo{
		Path: fileInfoFeed.Path,
		Hash: "", // TODO: Add
		// TODO: change types pkg to reduce mem footprint (Inode, Device, Mode)
		Inode:  int(fileInfoFeed.Inode),
		Device: int(fileInfoFeed.Dev),
		Ctime:  time.Unix(0, int64(fileInfoFeed.Ctime)),
		Mode:   int(fileInfoFeed.InodeMode),
	}
}

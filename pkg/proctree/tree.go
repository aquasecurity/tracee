package proctree

// Process Tree Documentation
//
// The process tree only exports read operations to the user - the user can query for processes and
// threads information. However, the process tree itself is rather complex and should not be changed
// by unsupported methods.
//
// Currently, the only supported way to update and change the process tree is via events. The
// process tree is aware of Tracee's events and knows how to update itself using these events. This
// can be done either using a pipeline or directly using the appropriate method.
//
// # Synchronization
//
// The tree's usage is not synchronized. Process information may be requested some time after it has
// been updated or even deleted. To address this issue, the tree:
//
// 1. Makes processes available even after they have exited and should have been deleted for some
//    time.
// 2. Exports processes and threads information according to a specific time, instead of providing
//    all the information and leaving the user to process it.
//
// # Events feeding and edge case handling
//
// The overall design of the tree takes into consideration that events are not guaranteed to be
// ordered, nor are they guaranteed to arrive at all. Moreover, the tree needs to account for the
// fact that it starts running in the middle of the system runtime. As a result, it misses some
// process fork, exec, and exit events.
//
// To withstand these issues, the tree does the following:
//
// 1. Limits the number of nodes it keeps to avoid leakage when missing exit events.
// 2. Gathers information from all events, even those that are not related to process and thread
//    life cycles.
// 3. Attempts to clean processes with a PID that is found to be reused by new fork events.
// 4. Initializes parent process nodes, even with minimal information, to establish connections
//    between known nodes.
// 5. The tree does *not* attempt to create one large tree, but instead adopts a forest
//    architecture. Since it does not have all the history, it can't connect all nodes, so it only
//    connects nodes it knows are connected.
//

import (
	"fmt"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils/types"
	"github.com/aquasecurity/tracee/types/datasource"
	"github.com/aquasecurity/tracee/types/trace"
)

// nodeUniqueId is a set of information which should be unique enough to identify a node from
// another at all cases.
type nodeUniqueId struct {
	id         int
	uniqueTime int
}

// gcNode is a node which support being cleaned from the process tree.
// All the nodes followed by the process tree has to implement this interface.
type gcNode interface {
	// GetUniqueId generates the unique ID to identify the node with in the tree.
	GetUniqueId() nodeUniqueId
	// DisconnectNode remove all references from the node to other nodes and vice versa.
	// There should be no connections to and from the node after this is called.
	DisconnectNode()
}

type ProcessTreeConfig struct {
	// Max amount of processes nodes to allow in memory.
	// Too small value here might result missing information in the tree and inconsistency.
	// Default recommended value is 32768, as this is the max amount of PIDs in the system.
	// You might even want more than 32768 to allow relevant information of dead processes to be
	// available after their exit.
	MaxProcesses int
	// Max amount of threads nodes to allow in memory.
	// Too small value here might result missing information in the tree and inconsistency.
	// Default recommended value is 32768, as this is the max amount of TIDs in the system.
	// You might even want more than 32768 to allow relevant information of dead threads to be
	// available after their exit.
	MaxThreads int
	// Max size (in items) of cache for processes removing after exit - translates to the delay
	// between process exit to its removal from the tree (if it is not interesting after its death).
	// Too small value here might result processes missing from tree after their exit, before
	// users were able to query the process information because of the delay between the feeding
	// of the tree and the consumption of its information.
	MaxCacheDelete int
}

// ProcessTree is a struct which follow the state of processes during runtime of a system.
// The process tree is updated through Tracee's events, and is designed to overcome problems that
// may arise because of events consumption (like handling lost events).
// For more information on the logic, please go to the package documentation.
type ProcessTree struct {
	processes types.RWMap[int, *processNode]
	threads   types.RWMap[int, *threadNode]
	// A cache responsible for limiting the amount of memory used by processes nodes, and clean them
	// from memory.
	processesGC *lru.Cache[nodeUniqueId, *processNode]
	// A cache responsible for limiting the amount of memory used by threads nodes, and clean them
	// from memory.
	threadsGC *lru.Cache[nodeUniqueId, *threadNode]
	// A cache for dead processes nodes before removing them, allowing them to be available after
	// deletion was initialized for some time.
	deadProcessesCache *lru.Cache[int, bool]
}

func NewProcessTree(config ProcessTreeConfig) (*ProcessTree, error) {
	tree := &ProcessTree{
		processes: types.InitRWMap[int, *processNode](),
		threads:   types.InitRWMap[int, *threadNode](),
	}
	cache, err := lru.NewWithEvict[int, bool](
		config.MaxCacheDelete,
		func(dpid int, _ bool) {
			tree.removeProcessFromTree(dpid, false)
		})
	if err != nil {
		return nil, err
	}
	processesGC, err := lru.NewWithEvict[nodeUniqueId, *processNode](
		config.MaxProcesses,
		// This function remove the process from the tree and allow it to be garbage collected by
		// disconnecting it from all other nodes
		func(id nodeUniqueId, node *processNode) {
			err = tree.deleteProcess(node)
			if err != nil {
				logger.Errorw("delete process from tree", "err", err.Error())
			}
		},
	)
	if err != nil {
		return nil, err
	}
	threadsGC, err := lru.NewWithEvict[nodeUniqueId, *threadNode](
		config.MaxThreads,
		// This function remove the thread from the tree and allow it to be garbage collected by
		// disconnecting it from all other nodes
		func(id nodeUniqueId, node *threadNode) {
			err = tree.deleteThread(node)
			if err != nil {
				logger.Errorw("delete thread from tree", "err", err.Error())
			}
		},
	)
	if err != nil {
		return nil, err
	}
	tree.deadProcessesCache = cache
	tree.processesGC = processesGC
	tree.threadsGC = threadsGC
	return tree, nil
}

// GetProcessInfo return the process information from the process tree relevant to the given time
func (tree *ProcessTree) GetProcessInfo(hostProcessID int, queryTime time.Time) (datasource.ProcessInfo, error) {
	pn, err := tree.getProcess(hostProcessID)
	if err != nil {
		return datasource.ProcessInfo{}, err
	}
	return pn.export(queryTime), nil
}

// GetThreadInfo return the thread information from the process tree relevant to the given time
func (tree *ProcessTree) GetThreadInfo(hostThreadId int, queryTime time.Time) (datasource.ThreadInfo, error) {
	tn, err := tree.getThread(hostThreadId)
	if err != nil {
		return datasource.ThreadInfo{}, err
	}
	return tn.export(queryTime), nil
}

// GetProcessLineage return list of processes, starting with given PID process and moving upward,
// of the ancestors of the process.
// This is done up to the given max depth, or either last known ancestor or the container root.
// The information of the process with given PID is relevant to the given time, and the ancestors
// information are each relevant to their lineage child fork time. This should help to provide
// information regarding the lineage which is relevant to given process.
func (tree *ProcessTree) GetProcessLineage(hostProcessID int, queryTime time.Time, maxDepth int) (datasource.ProcessLineage, error) {
	pList, err := tree.getProcessLineage(hostProcessID, maxDepth)
	if err != nil {
		return nil, err
	}
	lineage := make(datasource.ProcessLineage, len(pList))
	relevantTime := queryTime
	for i, p := range pList {
		lineage[i] = p.export(relevantTime)
		relevantTime = lineage[i].StartTime
	}
	return lineage, nil
}

// getProcessLineage returns list of processes starting with the PID matching process back to the
// root of the container or oldest registered ancestor in the container (if root is missing).
// You can cap the amount of ancestors given this way with the maxDepth argument.
func (tree *ProcessTree) getProcessLineage(hostProcessID int, maxDepth int) ([]*processNode, error) {
	process, err := tree.getProcess(hostProcessID)
	if err != nil {
		return nil, err
	}
	var lineage []*processNode
	depth := 0
	for process != nil && depth <= maxDepth {
		lineage = append(lineage, process)
		process.mutex.RLock()
		parent := process.getParent()
		process.mutex.RUnlock()
		process = parent
		depth++
	}
	return lineage, nil
}

// getProcess get the process node from the process tree if exists, and return error if not.
func (tree *ProcessTree) getProcess(hostProcessID int) (*processNode, error) {
	process, ok := tree.processes.Get(hostProcessID)
	if !ok {
		return nil, fmt.Errorf("no process with given Id is recorded")
	}
	// Update node usage in the GC cache
	_, _ = tree.processesGC.Get(process.GetUniqueId())
	return process, nil
}

// setProcess add the process node to the process tree
func (tree *ProcessTree) setProcess(pnode *processNode) error {
	tree.processes.Set(pnode.getPid(), pnode)
	ok, _ := tree.processesGC.ContainsOrAdd(pnode.GetUniqueId(), pnode)
	// If exists, we want to update its last usage
	if ok {
		tree.processesGC.Get(pnode.GetUniqueId())
	}
	return nil
}

// hasProcess return if the process is accessible through the tree
func (tree *ProcessTree) hasProcess(hostProcessID int) bool {
	pnode, exist := tree.processes.Get(hostProcessID)
	// If exists, we want to update its last usage
	if exist {
		tree.processesGC.Get(pnode.GetUniqueId())
	}
	return exist
}

// removeProcess remove the process node from the process tree
// This does not remove references to it from other nodes and vice versa, nor allow it to be
// garbage collected.
func (tree *ProcessTree) removeProcess(pnode *processNode) error {
	tree.processes.Delete(pnode.getPid())
	return nil
}

// cleanProcess remove the process from the GC LRU, triggering cleaning eviction function
func (tree *ProcessTree) cleanProcess(pnode *processNode) error {
	_ = tree.processesGC.Remove(pnode.GetUniqueId())
	return nil
}

// deleteProcess remove the process node from the process tree and delete all references to it,
// so it could be garbage collected
func (tree *ProcessTree) deleteProcess(pnode *processNode) error {
	tree.deleteNodeAndDeadAncestors(pnode)
	return nil
}

// getThread get the thread node from the process tree if exists, and return error if not.
func (tree *ProcessTree) getThread(hostThreadId int) (*threadNode, error) {
	thread, ok := tree.threads.Get(hostThreadId)
	if !ok {
		return nil, fmt.Errorf("no thread with given Id is recorded")
	}
	// Update node usage in the GC cache
	_, _ = tree.threadsGC.Get(thread.GetUniqueId())
	return thread, nil
}

// setThread add the thread node to the process tree
func (tree *ProcessTree) setThread(tnode *threadNode) error {
	tree.threads.Set(tnode.getTid(), tnode)
	ok, _ := tree.threadsGC.ContainsOrAdd(tnode.GetUniqueId(), tnode)
	// If exists, we want to update its last usage
	if ok {
		tree.threadsGC.Get(tnode.GetUniqueId())
	}
	return nil
}

// hasThread return if the thread is accessible through the tree
func (tree *ProcessTree) hasThread(hostThreadID int) bool {
	tnode, exist := tree.threads.Get(hostThreadID)
	// If exists, we want to update its last usage
	if exist {
		tree.threadsGC.Get(tnode.GetUniqueId())
	}
	return exist
}

// removeProcess remove the process node from the process tree
// This does not remove references to it from other nodes and vice versa, nor allow it to be
// garbage collected.
func (tree *ProcessTree) removeThread(tnode *threadNode) error {
	tree.threads.Delete(tnode.getTid())
	return nil
}

// cleanThread remove the thread from the GC LRU, triggering cleaning eviction function
func (tree *ProcessTree) cleanThread(tnode *threadNode) error {
	_ = tree.threadsGC.Remove(tnode.GetUniqueId())
	return nil
}

// deleteThread remove the thread node from the process tree and delete all references to it,
// so it could be garbage collected
func (tree *ProcessTree) deleteThread(tnode *threadNode) error {
	err := tree.removeThread(tnode)
	if err != nil {
		logger.Errorw("delete thread from tree", "err", err.Error())
	}
	tnode.DisconnectNode()
	return nil
}

// addGeneralEventProcess generate a new process with information that could be received from any
// event from the process
func (tree *ProcessTree) addGeneralEventProcess(event *trace.Event) (*processNode, error) {
	process, err := tree.newProcessNode(event.HostProcessID)
	if err != nil {
		return nil, err
	}
	process.setGeneralInfoFromEventOnce(event)
	return process, nil
}

// addGeneralEventThread generate a new thread with information that could be received from any
// event from the thread
func (tree *ProcessTree) addGeneralEventThread(event *trace.Event) (*threadNode, error) {
	p, err := tree.getProcess(event.HostProcessID)
	if err != nil {
		p, err = tree.addGeneralEventProcess(event)
		if err != nil {
			return nil, err
		}
	}
	p.mutex.Lock()
	thread, err := tree.getOrCreateProcessThreadNode(p, event.HostThreadID)
	exitTime := p.getExitTime()
	p.mutex.Unlock()
	if err != nil {
		return nil, err
	}

	thread.setGeneralInfoFromEventOnce(event, exitTime)
	return thread, nil
}

// generateParentProcess add a parent process to given process from tree if existing or creates
// new node with the best effort info
func (tree *ProcessTree) generateParentProcess(parentHostId int, parentNsId int, process *processNode) (*processNode, error) {
	if parentNsId != 0 &&
		process.getPid() != parentHostId { // Prevent looped references
		parentProcess, err := tree.getProcess(parentHostId)
		if err != nil {
			// TODO: Fix the race condition here between checking if exist and setting new one
			parentProcess, err = tree.newProcessNode(parentHostId)
			if err != nil {
				return nil, err
			}
			parentProcess.setNsPid(parentNsId)
			if err != nil {
				return nil, err
			}
		}
		parentProcess.mutex.Lock()
		process.mutex.Lock()
		process.connectParent(parentProcess)
		parentProcess.connectChild(process)
		process.mutex.Unlock()
		parentProcess.mutex.Unlock()
	}
	return process, nil
}

// newProcessNode create a new processNode and sign it in the tree
func (tree *ProcessTree) newProcessNode(pid int) (*processNode, error) {
	proc, err := newProcessNode(pid)
	if err != nil {
		return nil, err
	}
	tree.processes.Set(pid, proc)
	tree.processesGC.Add(proc.GetUniqueId(), proc)
	return proc, nil
}

// newThreadNode create a new threadNode and sign it in the tree
func (tree *ProcessTree) newThreadNode(tid int) (*threadNode, error) {
	thread, err := newThreadNode(tid)
	if err != nil {
		return nil, err
	}
	tree.threads.Set(tid, thread)
	tree.threadsGC.Add(thread.GetUniqueId(), thread)
	return thread, nil
}

// getOrCreateProcessThreadNode add a new thread to a process, and also sign the thread in the tree.
// It will return existing one if there is one with the same ID.
func (tree *ProcessTree) getOrCreateProcessThreadNode(process *processNode, tid int) (*threadNode, error) {
	newThread, err := process.addThreadBasic(tid)
	if err != nil {
		return nil, err
	}
	if !tree.hasThread(newThread.getTid()) {
		err = tree.setThread(newThread)
	}
	return newThread, err
}

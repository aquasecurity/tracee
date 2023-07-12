package proctree

import (
	"fmt"
	"time"

	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/trace"
)

// ProcessExitEvent remove references of processes from the tree when the corresponding process
// exit without children, or if the last child process of a process exits.
// Notice that there is a danger of memory leak if there are lost events of sched_process_exit
// (but is limited to the possible number of PIds - 32768).
func (tree *ProcessTree) ProcessExitEvent(event *trace.Event) error {
	err := tree.processGeneralEvent(event)
	if err != nil {
		return err
	}
	process, err := tree.getProcess(event.HostProcessID)
	if err != nil {
		return fmt.Errorf("process was inserted to the treee but is missing right after")
	}
	thread, err := tree.getOrCreateProcessThreadNode(process, event.HostThreadID)
	if err != nil {
		return nil
	}
	thread.mutex.Lock()
	thread.setExitTime(time.Unix(0, int64(event.Timestamp)))
	thread.mutex.Unlock()

	processGroupExit, err := helpers.GetTraceeBoolArgumentByName(*event, "process_group_exit")
	if err != nil {
		return err
	}

	process.mutex.RLock()
	exitTime := process.getExitTime()
	process.mutex.RUnlock()
	// More than 1 thread exit might be given with the group exit flag. We want to do the process
	// exit just for the first event with the flag set.
	if processGroupExit && exitTime.UnixNano() == 0 {
		eventTimestamp := time.Unix(0, int64(event.Timestamp))
		process.mutex.Lock()
		process.setExitTime(eventTimestamp)
		threads := process.getThreads()
		process.mutex.Unlock()
		for _, tnode := range threads {
			tnode.mutex.Lock()
			tnode.setDefaultExitTime(eventTimestamp)
			tnode.mutex.Unlock()
		}
		tree.cachedRemoveProcess(process.getPid())
	}
	return nil
}

// cachedRemoveProcess remove the process from the tree in delay.
// This is done to keep the information of the process available in the process tree for some grace
// period before making it unavailable.
// To avoid uncontrolled leaking, the delay is determined by the amount of events already queued
// to be deleted.
// We have no reason to delete the information fast, only if we encountered PID reuse.
func (tree *ProcessTree) cachedRemoveProcess(pid int) {
	tree.deadProcessesCache.Add(pid, true)
}

// emptyDeadProcessesCache delete all processes queued to deletion, and empty the cache list.
func (tree *ProcessTree) emptyDeadProcessesCache() {
	tree.deadProcessesCache.Purge()
}

// removeProcessFromTree remove the given process from the tree, and remove its connections from
// its ancestors.
// However, we want to keep processes nodes as long as they have living children (or grandchildren,
// grand-grandchildren, etc.).
// To support this functionality,
// we don't remove process node if at least one of its children nodes is alive.
// To avoid memory leak, we delete also all ancestors of the process that have no living children.
// To enable immediate removal of the process node tree access (via getProcess method), the
// immediateRemoveAccess flag should be set. Useful if you need to overwrite process access.
func (tree *ProcessTree) removeProcessFromTree(dpid int, immediateRemoveAccess bool) {
	p, err := tree.getProcess(dpid)
	if err != nil {
		return
	}
	if immediateRemoveAccess {
		err = tree.removeProcess(p)
		if err != nil {
			logger.Errorw("remove process from tree", "err", err.Error())
		}
	}
	// Make sure that the process is not deleted because missed children
	if !p.hasChildren() {
		err = tree.cleanProcess(p)
		if err != nil {
			logger.Errorw("clean process from tree", "err", err.Error())
		}
	}
}

// deleteNodeAndDeadAncestors remove process and all dead ancestors so only processes
// which are alive or with living descendants will remain in the tree.
// All nodes removed this way are deleted - all references to them or from them are deleted.
// This should allow them to be garbage collected later on.
// This remove is recursive because of the GC LRU eviction function is calling it.
func (tree *ProcessTree) deleteNodeAndDeadAncestors(pn *processNode) {
	// TODO: Make this function atomic
	// TODO: Add a flag specifying that the node was cleaned, to avoid modification after cleaning
	err := tree.removeProcess(pn)
	if err != nil {
		logger.Errorw("remove process from tree", "err", err.Error())
	}
	pn.mutex.RLock()
	threads := pn.getThreads()
	parent := pn.getParent()
	pn.mutex.RUnlock()

	pn.DisconnectNode()
	for _, thread := range threads {
		err := tree.cleanThread(thread)
		if err != nil {
			logger.Errorw("clean thread from tree", "err", err.Error())
		}
	}
	if parent == nil {
		return
	}
	parent.mutex.RLock()
	// If parent is still alive, or it has living children nodes, we don't want to delete it
	shouldCleanParent := parent.exited() && !parent.hasChildren()
	parent.mutex.RUnlock()
	if shouldCleanParent {
		err := tree.cleanProcess(parent)
		if err != nil {
			logger.Errorw("clean parent process from tree", "err", err.Error())
		}
	}
}

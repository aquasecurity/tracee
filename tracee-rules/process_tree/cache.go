package process_tree

const cachedDeadEvents = 100

func (tree *ProcessTree) cachedDeleteProcess(pid int) {
	tree.deadProcessesCache = append(tree.deadProcessesCache, pid)
	if len(tree.deadProcessesCache) > cachedDeadEvents {
		dpid := tree.deadProcessesCache[0]
		tree.deadProcessesCache = tree.deadProcessesCache[1:]
		tree.deleteProcessFromTree(dpid)
	}
}

func (tree *ProcessTree) emptyDeadProcessesCache() {
	for _, dpid := range tree.deadProcessesCache {
		tree.deleteProcessFromTree(dpid)
	}
	tree.deadProcessesCache = []int{}
	return
}

func (tree *ProcessTree) deleteProcessFromTree(dpid int) {
	p, err := tree.GetProcessInfo(dpid)
	if err != nil {
		return
	}
	// Make sure that the process is not deleted because missed children or events
	if len(p.ChildProcesses) == 0 && p.IsAlive == false {
		delete(tree.processes, dpid)
	}
}

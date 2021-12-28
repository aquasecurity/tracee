package process_tree

const cachedDeadEvents = 100

func (tree *ProcessTree) cachedDeleteProcess(pid int) {
	tree.deadProcessesCache = append(tree.deadProcessesCache, pid)
	if len(tree.deadProcessesCache) > cachedDeadEvents {
		dpid := tree.deadProcessesCache[0]
		tree.deadProcessesCache = tree.deadProcessesCache[1:]
		p, _ := tree.GetProcessInfo(dpid)
		// Make sure that the process is not deleted because missed children or events
		if len(p.ChildProcesses) == 0 && p.IsAlive == false {
			delete(tree.processes, dpid)
		}
	}
}

func (tree *ProcessTree) EmptyProcessCache() {
	for _, dpid := range tree.deadProcessesCache {
		p, _ := tree.GetProcessInfo(dpid)
		// Make sure that the process is not deleted because missed children or events
		if len(p.ChildProcesses) == 0 && p.IsAlive == false {
			delete(tree.processes, dpid)
		}
	}
	tree.deadProcessesCache = []int{}
	return
}

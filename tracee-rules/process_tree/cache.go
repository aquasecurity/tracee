package process_tree

const cachedDeadEvents = 100

func (tree *ProcessTree) cachedDeleteProcess(pid int) {
	tree.deadProcessesCache = append(tree.deadProcessesCache, pid)
	if len(tree.deadProcessesCache) > cachedDeadEvents {
		dpid := tree.deadProcessesCache[0]
		tree.deadProcessesCache = tree.deadProcessesCache[1:]
		delete(tree.processes, dpid)
	}
}

func (tree *ProcessTree) EmptyProcessCache() {
	for _, dpid := range tree.deadProcessesCache {
		delete(tree.processes, dpid)
	}
	tree.deadProcessesCache = []int{}
	return
}

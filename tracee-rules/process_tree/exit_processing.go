package process_tree

import (
	"fmt"
	"github.com/aquasecurity/tracee/pkg/external"
)

// processExitEvent remove references of processes from the tree when the corresponding process exit without children, or
// if the last child process of a process exits.
// Notice that there is a danger of memory leak if there are lost events of sched_process_exit (but is limited to the
// possible number of PIDs - 32768)
func (tree *ProcessTree) processExitEvent(event *external.Event) error {
	err := tree.processDefaultEvent(event)
	if err != nil {
		return err
	}
	process, _ := tree.GetProcessInfo(event.HostProcessID)
	process.ThreadsExits[event.HostThreadID] = timestamp(event.Timestamp)

	argument, err := getArgumentByName(event, "process_group_exit")
	if err != nil {
		return err
	}
	processGroupExit, ok := argument.Value.(bool)
	if !ok {
		return fmt.Errorf("invalid type of argument '%s' - %T",
			argument.Name,
			argument.Value)
	}

	if processGroupExit {
		process.IsAlive = false
		process.ExitTime = timestamp(event.Timestamp)
		for tid, exitTime := range process.ThreadsExits {
			if exitTime == 0 {
				process.ThreadsExits[tid] = timestamp(event.Timestamp)
			}
		}
		tree.cachedDeleteProcess(process.InHostIDs.Pid)

	}
	return nil
}

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
	// Make sure that the process is not deleted because missed children
	if len(p.ChildProcesses) == 0 {
		// Remove process and all dead ancestors so only processes which are alive or with living descendants will remain.
		cp := p
		for {
			delete(tree.processes, cp.InHostIDs.Pid)
			if cp.ParentProcess == nil {
				break
			}
			for i, childProcess := range cp.ParentProcess.ChildProcesses {
				if childProcess == cp {
					cp.ParentProcess.ChildProcesses = append(cp.ParentProcess.ChildProcesses[:i],
						cp.ParentProcess.ChildProcesses[i+1:]...)
					break
				}
			}
			if cp.ParentProcess.IsAlive {
				break
			}
			cp = cp.ParentProcess
		}

	}
}

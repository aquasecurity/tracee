package process_tree

import "github.com/aquasecurity/tracee/pkg/external"

// processExitEvent remove references of processes from the tree when the corresponding process exit without children, or
// if the last child process of a process exits.
// Notice that there is a danger of memory leak if there are lost events of sched_process_exit
func (tree *ProcessTree) processExitEvent(event external.Event) error {
	process, err := tree.GetProcessInfo(event.HostProcessID)
	if err != nil {
		return err
	}
	process.ThreadsCount -= 1
	// In case of concurrent processing, this check will be problematic
	if process.ThreadsCount <= 0 {
		process.IsAlive = false
		// Remove process and all dead ancestors so only processes with alive descendants will remain.
		if len(process.ChildProcesses) == 0 {
			container, err := tree.getContainerTree(event.ContainerID)
			if err != nil {
				return err
			}
			cp := process
			for {
				tree.cachedDeleteProcess(cp.InHostIDs.Pid)
				if container.Root == cp {
					delete(tree.containers, event.ContainerID)
				}
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
	return nil
}

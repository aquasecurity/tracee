package process_tree

import (
	"fmt"
	"github.com/aquasecurity/tracee/pkg/external"
)

// processExitEvent remove references of processes from the tree when the corresponding process exit without children, or
// if the last child process of a process exits.
// Notice that there is a danger of memory leak if there are lost events of sched_process_exit (but is limited to the
// possible number of PIDs - 32768)
func (tree *ProcessTree) processExitEvent(event external.Event) error {
	process, err := tree.GetProcessInfo(event.HostProcessID)
	if err != nil {
		return err
	}
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

	// In case of concurrent processing, this check will be problematic
	if processGroupExit {
		process.IsAlive = false
		process.ExitTime = timestamp(event.Timestamp)
		// Remove process and all dead ancestors so only processes with alive descendants will remain.
		if len(process.ChildProcesses) == 0 {
			cp := process
			for {
				tree.cachedDeleteProcess(cp.InHostIDs.Pid)
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

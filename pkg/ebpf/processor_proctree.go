package ebpf

import (
	"fmt"

	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/pkg/logger"
	traceetime "github.com/aquasecurity/tracee/pkg/time"
	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/aquasecurity/tracee/types/trace"
)

//
// Process Lifecycle (will feed the process tree)
//

// procTreeForkProcessor handles process fork events.
func (t *Tracee) procTreeForkProcessor(event *trace.Event) error {
	if t.processTree == nil {
		return fmt.Errorf("process tree is disabled")
	}

	var err error
	// NOTE: override all the fields of the forkFeed, to avoid any previous data.
	forkFeed := t.processTree.GetForkFeedFromPool()
	defer t.processTree.PutForkFeedInPool(forkFeed)

	// NOTE: The "parent" related arguments can be ignored for process tree purposes.

	// Parent Process (Go up in hierarchy until parent is a process and not a lwp)
	forkFeed.ParentTid, err = parse.ArgVal[int32](event.Args, "parent_process_tid")
	if err != nil {
		return err
	}
	forkFeed.ParentNsTid, err = parse.ArgVal[int32](event.Args, "parent_process_ns_tid")
	if err != nil {
		return err
	}
	forkFeed.ParentPid, err = parse.ArgVal[int32](event.Args, "parent_process_pid")
	if err != nil {
		return err
	}
	forkFeed.ParentNsPid, err = parse.ArgVal[int32](event.Args, "parent_process_ns_pid")
	if err != nil {
		return err
	}
	forkFeed.ParentStartTime, err = parse.ArgVal[uint64](event.Args, "parent_process_start_time")
	if err != nil {
		return err
	}

	// Thread Group Leader (might be the same as the "child", if "child" is a process)
	forkFeed.LeaderTid, err = parse.ArgVal[int32](event.Args, "leader_tid")
	if err != nil {
		return err
	}
	forkFeed.LeaderNsTid, err = parse.ArgVal[int32](event.Args, "leader_ns_tid")
	if err != nil {
		return err
	}
	forkFeed.LeaderPid, err = parse.ArgVal[int32](event.Args, "leader_pid")
	if err != nil {
		return err
	}
	forkFeed.LeaderNsPid, err = parse.ArgVal[int32](event.Args, "leader_ns_pid")
	if err != nil {
		return err
	}
	forkFeed.LeaderStartTime, err = parse.ArgVal[uint64](event.Args, "leader_start_time")
	if err != nil {
		return err
	}

	// Child (might be a process or a thread)
	forkFeed.ChildTid, err = parse.ArgVal[int32](event.Args, "child_tid")
	if err != nil {
		return err
	}
	forkFeed.ChildNsTid, err = parse.ArgVal[int32](event.Args, "child_ns_tid")
	if err != nil {
		return err
	}
	forkFeed.ChildPid, err = parse.ArgVal[int32](event.Args, "child_pid")
	if err != nil {
		return err
	}
	forkFeed.ChildNsPid, err = parse.ArgVal[int32](event.Args, "child_ns_pid")
	if err != nil {
		return err
	}
	forkFeed.ChildStartTime, err = parse.ArgVal[uint64](event.Args, "start_time") // child_start_time
	if err != nil {
		return err
	}
	forkFeed.TimeStamp = forkFeed.ChildStartTime // event timestamp is the same

	// Calculate hashes
	forkFeed.ParentHash = utils.HashTaskID(uint32(forkFeed.ParentTid), uint64(forkFeed.ParentStartTime))
	forkFeed.ChildHash = utils.HashTaskID(uint32(forkFeed.ChildTid), uint64(forkFeed.ChildStartTime))
	forkFeed.LeaderHash = utils.HashTaskID(uint32(forkFeed.LeaderTid), uint64(forkFeed.LeaderStartTime))

	return t.processTree.FeedFromFork(forkFeed)
}

// procTreeExecProcessor handles process exec events.
func (t *Tracee) procTreeExecProcessor(event *trace.Event) error {
	if t.processTree == nil {
		return fmt.Errorf("process tree is disabled")
	}
	if event.HostProcessID != event.HostThreadID {
		return nil // chek FeedFromExec for TODO of execve() handled by threads
	}

	var err error

	// NOTE: override all the fields of the execFeed, to avoid any previous data.
	execFeed := t.processTree.GetExecFeedFromPool()
	defer t.processTree.PutExecFeedInPool(execFeed)

	// Executable
	execFeed.CmdPath, err = parse.ArgVal[string](event.Args, "cmdpath")
	if err != nil {
		return err
	}
	execFeed.PathName, err = parse.ArgVal[string](event.Args, "pathname")
	if err != nil {
		return err
	}
	execFeed.Dev, err = parse.ArgVal[uint32](event.Args, "dev")
	if err != nil {
		return err
	}
	execFeed.Inode, err = parse.ArgVal[uint64](event.Args, "inode")
	if err != nil {
		return err
	}
	execFeed.Ctime, err = parse.ArgVal[uint64](event.Args, "ctime")
	if err != nil {
		return err
	}
	execFeed.InodeMode, err = parse.ArgVal[uint16](event.Args, "inode_mode")
	if err != nil {
		return err
	}

	// // Binary Interpreter (or Loader): might come empty from the kernel
	// execFeed.InterpreterPath, _ := parse.ArgVal[string](event.Args, "interpreter_pathname")
	// execFeed.InterpreterDev, _ := parse.ArgVal[uint32](event.Args, "interpreter_dev")
	// execFeed.InterpreterInode, _ := parse.ArgVal[uint64](event.Args, "interpreter_inode")
	// execFeed.InterpreterCtime, _ := parse.ArgVal[uint64](event.Args, "interpreter_ctime")

	// Real Interpreter
	execFeed.Interp, err = parse.ArgVal[string](event.Args, "interp")
	if err != nil {
		return err
	}

	// Others
	execFeed.StdinType, err = parse.ArgVal[uint16](event.Args, "stdin_type")
	if err != nil {
		return err
	}
	execFeed.StdinPath, err = parse.ArgVal[string](event.Args, "stdin_path")
	if err != nil {
		return err
	}
	execFeed.InvokedFromKernel, err = parse.ArgVal[int32](event.Args, "invoked_from_kernel")
	if err != nil {
		return err
	}

	execFeed.TimeStamp = uint64(event.Timestamp)
	execFeed.TaskHash = utils.HashTaskID(uint32(event.HostThreadID), uint64(event.ThreadStartTime))
	execFeed.ParentHash = 0 // regular pipeline does not have parent hash
	execFeed.LeaderHash = 0 // regular pipeline does not have leader hash

	return t.processTree.FeedFromExec(execFeed)
}

// procTreeExitProcessor handles process exit events.
func (t *Tracee) procTreeExitProcessor(event *trace.Event) error {
	if t.processTree == nil {
		return fmt.Errorf("process tree is disabled")
	}
	if event.HostProcessID != event.HostThreadID {
		return nil // chek FeedFromExec for TODO of execve() handled by threads
	}

	// NOTE: Currently FeedFromExit is only using TaskHash and TimeStamp from the ExitFeed.
	// So the other fields are commented out for now.
	//
	// TODO: Analyze if the other fields will be needed in the future.
	// var err error

	// NOTE: override all the fields of the exitFeed, to avoid any previous data.
	exitFeed := t.processTree.GetExitFeedFromPool()
	defer t.processTree.PutExitFeedInPool(exitFeed)

	// // Exit logic arguments
	// exitFeed.ExitCode, err = parse.ArgVal[int32](event.Args, "exit_code")
	// if err != nil {
	// 	return err
	// }
	// exitFeed.Group, err = parse.ArgVal[bool](event.Args, "process_group_exit")
	// if err != nil {
	// 	return err
	// }

	exitFeed.TimeStamp = uint64(event.Timestamp) // time of exit is already a timestamp
	exitFeed.TaskHash = utils.HashTaskID(uint32(event.HostThreadID), uint64(event.ThreadStartTime))
	// exitFeed.ParentHash = 0 // regular pipeline does not have parent hash
	// exitFeed.LeaderHash = 0 // regular pipeline does not have leader hash

	return t.processTree.FeedFromExit(exitFeed)
}

//
// Processors that enrich events with process tree information
//

// procTreeAddBinInfo enriches the event with processes information from the process tree.
func (t *Tracee) procTreeAddBinInfo(event *trace.Event) error {
	currentProcess, procOk := t.processTree.GetProcessByHash(event.ProcessEntityId)
	if !procOk {
		_, threadOk := t.processTree.GetThreadByHash(event.ProcessEntityId)
		if !threadOk {
			logger.Debugw(
				"error enriching event executable info",
				"pid", event.HostProcessID,
				"tid", event.HostThreadID,
				"event name", event.EventName,
				"timestamp", event.Timestamp,
				"error", "not found in process tree",
			)
		}
		return nil // threads don't have executable info in the process tree
	}

	// Event timestamp is changed to relative (or not) at the end of all processors only.
	eventTimestamp := traceetime.NsSinceEpochToTime(uint64(event.Timestamp))

	executable := currentProcess.GetExecutable()

	// Update the event with the executable information from the process tree.
	event.Executable.Path = executable.GetPathAt(eventTimestamp)

	// TODO: feed executable information from procfs during proctree initialization.

	return nil
}

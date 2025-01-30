package controlplane

import (
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/pkg/time"
	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/aquasecurity/tracee/types/trace"
)

//
// Processes Lifecycle (will feed the process tree)
//

func (ctrl *Controller) procTreeForkProcessor(args []trace.Argument) error {
	if ctrl.processTree == nil {
		return nil // process tree is disabled
	}

	var err error
	// NOTE: override all the fields of the forkFeed, to avoid any previous data.
	forkFeed := ctrl.processTree.GetForkFeedFromPool()
	defer ctrl.processTree.PutForkFeedInPool(forkFeed)

	// NOTE: The "parent" related arguments can be ignored for process tree purposes.

	// Process & Event identification arguments
	forkFeed.TimeStamp, err = parse.ArgVal[uint64](args, "timestamp")
	if err != nil {
		return err
	}

	// Parent Process (Go up in hierarchy until parent is a process and not a lwp)
	forkFeed.ParentTid, err = parse.ArgVal[int32](args, "parent_process_tid")
	if err != nil {
		return err
	}
	forkFeed.ParentNsTid, err = parse.ArgVal[int32](args, "parent_process_ns_tid")
	if err != nil {
		return err
	}
	forkFeed.ParentPid, err = parse.ArgVal[int32](args, "parent_process_pid")
	if err != nil {
		return err
	}
	forkFeed.ParentNsPid, err = parse.ArgVal[int32](args, "parent_process_ns_pid")
	if err != nil {
		return err
	}
	forkFeed.ParentStartTime, err = parse.ArgVal[uint64](args, "parent_process_start_time")
	if err != nil {
		return err
	}

	// Thread Group Leader (might be the same as the "child", if "child" is a process)
	forkFeed.LeaderTid, err = parse.ArgVal[int32](args, "leader_tid")
	if err != nil {
		return err
	}
	forkFeed.LeaderNsTid, err = parse.ArgVal[int32](args, "leader_ns_tid")
	if err != nil {
		return err
	}
	forkFeed.LeaderPid, err = parse.ArgVal[int32](args, "leader_pid")
	if err != nil {
		return err
	}
	forkFeed.LeaderNsPid, err = parse.ArgVal[int32](args, "leader_ns_pid")
	if err != nil {
		return err
	}
	forkFeed.LeaderStartTime, err = parse.ArgVal[uint64](args, "leader_start_time")
	if err != nil {
		return err
	}

	// Child (might be a process or a thread)
	forkFeed.ChildTid, err = parse.ArgVal[int32](args, "child_tid")
	if err != nil {
		return err
	}
	forkFeed.ChildNsTid, err = parse.ArgVal[int32](args, "child_ns_tid")
	if err != nil {
		return err
	}
	forkFeed.ChildPid, err = parse.ArgVal[int32](args, "child_pid")
	if err != nil {
		return err
	}
	forkFeed.ChildNsPid, err = parse.ArgVal[int32](args, "child_ns_pid")
	if err != nil {
		return err
	}
	forkFeed.ChildStartTime, err = parse.ArgVal[uint64](args, "start_time") // child_start_time
	if err != nil {
		return err
	}

	forkFeed.TimeStamp = time.BootToEpochNS(forkFeed.TimeStamp)
	forkFeed.ChildStartTime = time.BootToEpochNS(forkFeed.ChildStartTime)
	forkFeed.ParentStartTime = time.BootToEpochNS(forkFeed.ParentStartTime)
	forkFeed.LeaderStartTime = time.BootToEpochNS(forkFeed.LeaderStartTime)

	forkFeed.ChildHash = utils.HashTaskID(uint32(forkFeed.ChildTid), forkFeed.ChildStartTime)
	forkFeed.ParentHash = utils.HashTaskID(uint32(forkFeed.ParentTid), forkFeed.ParentStartTime)
	forkFeed.LeaderHash = utils.HashTaskID(uint32(forkFeed.LeaderTid), forkFeed.LeaderStartTime)

	return ctrl.processTree.FeedFromFork(forkFeed)
}

func (ctrl *Controller) procTreeExecProcessor(args []trace.Argument) error {
	if ctrl.processTree == nil {
		return nil // process tree is disabled
	}

	var err error

	// NOTE: override all the fields of the execFeed, to avoid any previous data.
	execFeed := ctrl.processTree.GetExecFeedFromPool()
	defer ctrl.processTree.PutExecFeedInPool(execFeed)

	// Process & Event identification arguments (won't exist for regular events)
	execFeed.TimeStamp, err = parse.ArgVal[uint64](args, "timestamp")
	if err != nil {
		return err
	}
	execFeed.TaskHash, _ = parse.ArgVal[uint32](args, "task_hash")
	execFeed.ParentHash, _ = parse.ArgVal[uint32](args, "parent_hash")
	execFeed.LeaderHash, _ = parse.ArgVal[uint32](args, "leader_hash")

	// Executable
	execFeed.CmdPath, err = parse.ArgVal[string](args, "cmdpath")
	if err != nil {
		return err
	}
	execFeed.PathName, err = parse.ArgVal[string](args, "pathname")
	if err != nil {
		return err
	}
	execFeed.Dev, err = parse.ArgVal[uint32](args, "dev")
	if err != nil {
		return err
	}
	execFeed.Inode, err = parse.ArgVal[uint64](args, "inode")
	if err != nil {
		return err
	}
	execFeed.Ctime, err = parse.ArgVal[uint64](args, "ctime")
	if err != nil {
		return err
	}
	execFeed.InodeMode, err = parse.ArgVal[uint16](args, "inode_mode")
	if err != nil {
		return err
	}

	// // Binary Interpreter (or Loader): might come empty from the kernel
	// InterpreterPath, _ := parse.ArgVal[string](args, "interpreter_pathname")
	// InterpreterDev, _ := parse.ArgVal[uint32](args, "interpreter_dev")
	// InterpreterInode, _ := parse.ArgVal[uint64](args, "interpreter_inode")
	// InterpreterCtime, _ := parse.ArgVal[uint64](args, "interpreter_ctime")

	// Real Interpreter
	execFeed.Interp, err = parse.ArgVal[string](args, "interp")
	if err != nil {
		return err
	}

	// Others
	execFeed.StdinType, err = parse.ArgVal[uint16](args, "stdin_type")
	if err != nil {
		return err
	}
	execFeed.StdinPath, err = parse.ArgVal[string](args, "stdin_path")
	if err != nil {
		return err
	}
	execFeed.InvokedFromKernel, err = parse.ArgVal[int32](args, "invoked_from_kernel")
	if err != nil {
		return err
	}

	return ctrl.processTree.FeedFromExec(execFeed)
}

func (ctrl *Controller) procTreeExitProcessor(args []trace.Argument) error {
	if ctrl.processTree == nil {
		return nil // process tree is disabled
	}

	// NOTE: Currently FeedFromExit is only using TaskHash and TimeStamp from the ExitFeed.
	// So the other fields are commented out for now.
	//
	// TODO: Analyze if the other fields will be needed in the future.
	var err error

	// NOTE: override all the fields of the exitFeed, to avoid any previous data.
	exitFeed := ctrl.processTree.GetExitFeedFromPool()
	defer ctrl.processTree.PutExitFeedInPool(exitFeed)

	// Process & Event identification arguments (won't exist for regular events)
	exitFeed.TimeStamp, err = parse.ArgVal[uint64](args, "timestamp")
	if err != nil {
		return err
	}
	// time of exit is already a timestamp)
	exitFeed.TimeStamp = time.BootToEpochNS(exitFeed.TimeStamp)

	exitFeed.TaskHash, err = parse.ArgVal[uint32](args, "task_hash")
	if err != nil {
		return err
	}
	// exitFeed.ParentHash, err = parse.ArgVal[uint32](args, "parent_hash")
	// if err != nil {
	// 	return err
	// }
	// exitFeed.LeaderHash, err = parse.ArgVal[uint32](args, "leader_hash")
	// if err != nil {
	// 	return err
	// }

	// // Exit logic arguments
	// exitFeed.ExitCode, err = parse.ArgVal[int32](args, "exit_code")
	// if err != nil {
	// 	return err
	// }
	// exitFeed.SignalCode, err = parse.ArgVal[int32](args, "signal_code")
	// if err != nil {
	// 	return err
	// }
	// exitFeed.Group, err = parse.ArgVal[bool](args, "process_group_exit")
	// if err != nil {
	// 	return err
	// }

	return ctrl.processTree.FeedFromExit(exitFeed)
}

package controlplane

import (
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/pkg/proctree"
	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/aquasecurity/tracee/types/trace"
)

//
// Processes Lifecycle (will feed the process tree)
//

func (ctrl *Controller) procTreeForkProcessor(args []trace.Argument) error {
	var errs []error

	if ctrl.processTree == nil {
		return nil // process tree is disabled
	}

	// NOTE: The "parent" related arguments can be ignored for process tree purposes.

	// Process & Event identification arguments
	timestamp, err := parse.ArgVal[uint64](args, "timestamp")
	errs = append(errs, err)

	// Parent Process (Go up in hierarchy until parent is a process and not a lwp)
	parentTid, err := parse.ArgVal[int32](args, "parent_process_tid")
	errs = append(errs, err)
	parentNsTid, err := parse.ArgVal[int32](args, "parent_process_ns_tid")
	errs = append(errs, err)
	parentPid, err := parse.ArgVal[int32](args, "parent_process_pid")
	errs = append(errs, err)
	parentNsPid, err := parse.ArgVal[int32](args, "parent_process_ns_pid")
	errs = append(errs, err)
	parentStartTime, err := parse.ArgVal[uint64](args, "parent_process_start_time")
	errs = append(errs, err)

	// Thread Group Leader (might be the same as the "child", if "child" is a process)
	leaderTid, err := parse.ArgVal[int32](args, "leader_tid")
	errs = append(errs, err)
	leaderNsTid, err := parse.ArgVal[int32](args, "leader_ns_tid")
	errs = append(errs, err)
	leaderPid, err := parse.ArgVal[int32](args, "leader_pid")
	errs = append(errs, err)
	leaderNsPid, err := parse.ArgVal[int32](args, "leader_ns_pid")
	errs = append(errs, err)
	leaderStartTime, err := parse.ArgVal[uint64](args, "leader_start_time")
	errs = append(errs, err)

	// Child (might be a process or a thread)
	childTid, err := parse.ArgVal[int32](args, "child_tid")
	errs = append(errs, err)
	childNsTid, err := parse.ArgVal[int32](args, "child_ns_tid")
	errs = append(errs, err)
	childPid, err := parse.ArgVal[int32](args, "child_pid")
	errs = append(errs, err)
	childNsPid, err := parse.ArgVal[int32](args, "child_ns_pid")
	errs = append(errs, err)
	childStartTime, err := parse.ArgVal[uint64](args, "start_time") // child_start_time
	errs = append(errs, err)

	// Handle errors
	for _, err := range errs {
		if err != nil {
			return err
		}
	}

	childHash := utils.HashTaskID(uint32(childTid), childStartTime)
	parentHash := utils.HashTaskID(uint32(parentTid), parentStartTime)
	leaderHash := utils.HashTaskID(uint32(leaderTid), leaderStartTime)

	return ctrl.processTree.FeedFromFork(
		proctree.ForkFeed{
			TimeStamp:       uint64(ctrl.timeNormalizer.NormalizeTime(int(timestamp))),
			ChildHash:       childHash,
			ParentHash:      parentHash,
			LeaderHash:      leaderHash,
			ParentTid:       parentTid,
			ParentNsTid:     parentNsTid,
			ParentPid:       parentPid,
			ParentNsPid:     parentNsPid,
			ParentStartTime: uint64(ctrl.timeNormalizer.NormalizeTime(int(parentStartTime))),
			LeaderTid:       leaderTid,
			LeaderNsTid:     leaderNsTid,
			LeaderPid:       leaderPid,
			LeaderNsPid:     leaderNsPid,
			LeaderStartTime: uint64(ctrl.timeNormalizer.NormalizeTime(int(leaderStartTime))),
			ChildTid:        childTid,
			ChildNsTid:      childNsTid,
			ChildPid:        childPid,
			ChildNsPid:      childNsPid,
			ChildStartTime:  uint64(ctrl.timeNormalizer.NormalizeTime(int(childStartTime))),
		},
	)
}

func (ctrl *Controller) procTreeExecProcessor(args []trace.Argument) error {
	var errs []error

	if ctrl.processTree == nil {
		return nil // process tree is disabled
	}

	// Process & Event identification arguments (won't exist for regular events)
	timestamp, err := parse.ArgVal[uint64](args, "timestamp")
	errs = append(errs, err)
	taskHash, _ := parse.ArgVal[uint32](args, "task_hash")
	errs = append(errs, err)
	parentHash, _ := parse.ArgVal[uint32](args, "parent_hash")
	errs = append(errs, err)
	leaderHash, _ := parse.ArgVal[uint32](args, "leader_hash")
	errs = append(errs, err)

	// Executable
	cmdPath, err := parse.ArgVal[string](args, "cmdpath")
	errs = append(errs, err)
	pathName, err := parse.ArgVal[string](args, "pathname")
	errs = append(errs, err)
	dev, err := parse.ArgVal[uint32](args, "dev")
	errs = append(errs, err)
	inode, err := parse.ArgVal[uint64](args, "inode")
	errs = append(errs, err)
	ctime, err := parse.ArgVal[uint64](args, "ctime")
	errs = append(errs, err)
	inodeMode, err := parse.ArgVal[uint16](args, "inode_mode")
	errs = append(errs, err)

	// Binary Interpreter (or Loader): might come empty from the kernel
	interPathName, _ := parse.ArgVal[string](args, "interpreter_pathname")
	interDev, _ := parse.ArgVal[uint32](args, "interpreter_dev")
	interInode, _ := parse.ArgVal[uint64](args, "interpreter_inode")
	interCtime, _ := parse.ArgVal[uint64](args, "interpreter_ctime")

	// Real Interpreter
	interp, err := parse.ArgVal[string](args, "interp")
	errs = append(errs, err)

	// Others
	stdinType, err := parse.ArgVal[uint16](args, "stdin_type")
	errs = append(errs, err)
	stdinPath, err := parse.ArgVal[string](args, "stdin_path")
	errs = append(errs, err)
	invokedFromKernel, err := parse.ArgVal[int32](args, "invoked_from_kernel")
	errs = append(errs, err)

	// Handle errors
	for _, err := range errs {
		if err != nil {
			return err
		}
	}

	return ctrl.processTree.FeedFromExec(
		proctree.ExecFeed{
			TimeStamp:         uint64(ctrl.timeNormalizer.NormalizeTime(int(timestamp))),
			TaskHash:          taskHash,
			ParentHash:        parentHash,
			LeaderHash:        leaderHash,
			CmdPath:           cmdPath,
			PathName:          pathName,
			Dev:               dev,
			Inode:             inode,
			Ctime:             ctime,
			InodeMode:         inodeMode,
			InterpreterPath:   interPathName,
			InterpreterDev:    interDev,
			InterpreterInode:  interInode,
			InterpreterCtime:  interCtime,
			Interp:            interp,
			StdinType:         stdinType,
			StdinPath:         stdinPath,
			InvokedFromKernel: invokedFromKernel,
		},
	)
}

func (ctrl *Controller) procTreeExitProcessor(args []trace.Argument) error {
	var errs []error

	if ctrl.processTree == nil {
		return nil // process tree is disabled
	}

	// Process & Event identification arguments (won't exist for regular events)
	timestamp, err := parse.ArgVal[uint64](args, "timestamp")
	errs = append(errs, err)
	taskHash, err := parse.ArgVal[uint32](args, "task_hash")
	errs = append(errs, err)
	parentHash, err := parse.ArgVal[uint32](args, "parent_hash")
	errs = append(errs, err)
	leaderHash, err := parse.ArgVal[uint32](args, "leader_hash")
	errs = append(errs, err)

	// Exit logic arguments
	exitCode, err := parse.ArgVal[int64](args, "exit_code")
	errs = append(errs, err)
	groupExit, err := parse.ArgVal[bool](args, "process_group_exit")
	errs = append(errs, err)

	// Handle errors
	for _, err := range errs {
		if err != nil {
			return err
		}
	}

	return ctrl.processTree.FeedFromExit(
		proctree.ExitFeed{
			TimeStamp:  uint64(ctrl.timeNormalizer.NormalizeTime(int(timestamp))), // time of exit is already a timestamp
			TaskHash:   taskHash,
			ParentHash: parentHash,
			LeaderHash: leaderHash,
			ExitCode:   exitCode,
			Group:      groupExit,
		},
	)
}

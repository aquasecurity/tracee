package controlplane

import (
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/pkg/proctree"
	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/aquasecurity/tracee/types/trace"
)

//
// Processes Lifecycle
//

func (ctrl *Controller) processSchedProcessFork(args []trace.Argument) error {
	paramsLength := len(events.Core.GetDefinitionByID(events.SignalSchedProcessFork).GetParams())
	if len(args) != paramsLength {
		return errfmt.Errorf("got %d args instead of %d", len(args), paramsLength)
	}

	timestamp, err := parse.ArgVal[uint64](args, "timestamp")
	if err != nil {
		return errfmt.Errorf("error parsing timestamp: %v", err)
	}
	childHash, err := parse.ArgVal[uint32](args, "task_hash")
	if err != nil {
		return errfmt.Errorf("error parsing task_hash: %v", err)
	}
	parentHash, err := parse.ArgVal[uint32](args, "parent_hash")
	if err != nil {
		return errfmt.Errorf("error parsing parent_hash: %v", err)
	}
	leaderHash, err := parse.ArgVal[uint32](args, "leader_hash")
	if err != nil {
		return errfmt.Errorf("error parsing leader_hash: %v", err)
	}

	// Parent (the parent of the thread group leader, no matter if child is a process or LWP)

	parentTid, err := parse.ArgVal[int32](args, "parent_tid")
	if err != nil {
		return errfmt.Errorf("error parsing parent_tid: %v", err)
	}
	parentNsTid, err := parse.ArgVal[int32](args, "parent_ns_tid")
	if err != nil {
		return errfmt.Errorf("error parsing parent_ns_tid: %v", err)
	}
	parentPid, err := parse.ArgVal[int32](args, "parent_pid")
	if err != nil {
		return errfmt.Errorf("error parsing parent_pid: %v", err)
	}
	parentNsPid, err := parse.ArgVal[int32](args, "parent_ns_pid")
	if err != nil {
		return errfmt.Errorf("error parsing parent_ns_pid: %v", err)
	}
	parentStartTime, err := parse.ArgVal[uint64](args, "parent_start_time")
	if err != nil {
		return errfmt.Errorf("error parsing parent_start_time: %v", err)
	}

	// Thread Group Leader (might be the same as the "child", if "child" is a process)

	leaderTid, err := parse.ArgVal[int32](args, "leader_tid")
	if err != nil {
		return errfmt.Errorf("error parsing leader_tid: %v", err)
	}
	leaderNsTid, err := parse.ArgVal[int32](args, "leader_ns_tid")
	if err != nil {
		return errfmt.Errorf("error parsing leader_ns_tid: %v", err)
	}
	leaderPid, err := parse.ArgVal[int32](args, "leader_pid")
	if err != nil {
		return errfmt.Errorf("error parsing leader_pid: %v", err)
	}
	leaderNsPid, err := parse.ArgVal[int32](args, "leader_ns_pid")
	if err != nil {
		return errfmt.Errorf("error parsing leader_ns_pid: %v", err)
	}
	leaderStartTime, err := parse.ArgVal[uint64](args, "leader_start_time")
	if err != nil {
		return errfmt.Errorf("error parsing leader_start_time: %v", err)
	}

	// Child (might be a process or a thread)

	childTid, err := parse.ArgVal[int32](args, "child_tid")
	if err != nil {
		return errfmt.Errorf("error parsing child_tid: %v", err)
	}
	childNsTid, err := parse.ArgVal[int32](args, "child_ns_tid")
	if err != nil {
		return errfmt.Errorf("error parsing child_ns_tid: %v", err)
	}
	childPid, err := parse.ArgVal[int32](args, "child_pid")
	if err != nil {
		return errfmt.Errorf("error parsing child_pid: %v", err)
	}
	childNsPid, err := parse.ArgVal[int32](args, "child_ns_pid")
	if err != nil {
		return errfmt.Errorf("error parsing child_ns_pid: %v", err)
	}
	childStartTime, err := parse.ArgVal[uint64](args, "child_start_time")
	if err != nil {
		return errfmt.Errorf("error parsing child_start_time: %v", err)
	}

	// Sanity check: check if eBPF Hash matches userland Hash

	taskHashVerifier := utils.HashTaskID(uint32(childTid), childStartTime)
	parentHashVerifier := utils.HashTaskID(uint32(parentTid), parentStartTime)
	leaderHashVerifier := utils.HashTaskID(uint32(leaderTid), leaderStartTime)

	if childHash != taskHashVerifier ||
		parentHash != parentHashVerifier ||
		leaderHash != leaderHashVerifier {
		return errfmt.Errorf("eBPF Hash does not match")
	}

	return ctrl.processTree.FeedFromFork(
		proctree.ForkFeed{
			TimeStamp:       timestamp,
			ChildHash:       childHash,
			ParentHash:      parentHash,
			LeaderHash:      leaderHash,
			ParentTid:       parentTid,
			ParentNsTid:     parentNsTid,
			ParentPid:       parentPid,
			ParentNsPid:     parentNsPid,
			ParentStartTime: parentStartTime,
			LeaderTid:       leaderTid,
			LeaderNsTid:     leaderNsTid,
			LeaderPid:       leaderPid,
			LeaderNsPid:     leaderNsPid,
			LeaderStartTime: leaderStartTime,
			ChildTid:        childTid,
			ChildNsTid:      childNsTid,
			ChildPid:        childPid,
			ChildNsPid:      childNsPid,
			ChildStartTime:  childStartTime,
		},
	)
}

func (ctrl *Controller) processSchedProcessExec(args []trace.Argument) error {
	paramsLength := len(events.Core.GetDefinitionByID(events.SignalSchedProcessExec).GetParams())
	if len(args) != paramsLength {
		return errfmt.Errorf("got %d args instead of %d", len(args), paramsLength)
	}

	timestamp, err := parse.ArgVal[uint64](args, "timestamp")
	if err != nil {
		return errfmt.Errorf("error parsing timestamp: %v", err)
	}
	taskHash, err := parse.ArgVal[uint32](args, "task_hash")
	if err != nil {
		return errfmt.Errorf("error parsing task_hash: %v", err)
	}

	// Executable

	cmdPath, err := parse.ArgVal[string](args, "cmdpath")
	if err != nil {
		return errfmt.Errorf("error parsing cmdpath: %v", err)
	}
	pathName, err := parse.ArgVal[string](args, "pathname")
	if err != nil {
		return errfmt.Errorf("error parsing pathname: %v", err)
	}
	dev, err := parse.ArgVal[uint32](args, "dev")
	if err != nil {
		return errfmt.Errorf("error parsing dev: %v", err)
	}
	inode, err := parse.ArgVal[uint64](args, "inode")
	if err != nil {
		return errfmt.Errorf("error parsing inode: %v", err)
	}
	ctime, err := parse.ArgVal[uint64](args, "ctime")
	if err != nil {
		return errfmt.Errorf("error parsing ctime: %v", err)
	}
	inodeMode, err := parse.ArgVal[uint16](args, "inode_mode")
	if err != nil {
		return errfmt.Errorf("error parsing inode_mode: %v", err)
	}

	// Interpreter

	// these 4 fields might be empty, do not check of error
	interPathName, _ := parse.ArgVal[string](args, "interpreter_pathname")
	interDev, _ := parse.ArgVal[uint32](args, "interpreter_dev")
	interInode, _ := parse.ArgVal[uint64](args, "interpreter_inode")
	interCtime, _ := parse.ArgVal[uint64](args, "interpreter_ctime")

	interpreter, err := parse.ArgVal[string](args, "interp")
	if err != nil {
		return errfmt.Errorf("error parsing interp: %v", err)
	}

	// Other

	stdinType, err := parse.ArgVal[uint16](args, "stdin_type")
	if err != nil {
		return errfmt.Errorf("error parsing stdin_type: %v", err)
	}
	stdinPath, err := parse.ArgVal[string](args, "stdin_path")
	if err != nil {
		return errfmt.Errorf("error parsing stdin_path: %v", err)
	}
	invokedFromKernel, err := parse.ArgVal[int32](args, "invoked_from_kernel")
	if err != nil {
		return errfmt.Errorf("error parsing invoked_from_kernel: %v", err)
	}

	return ctrl.processTree.FeedFromExec(
		proctree.ExecFeed{
			TimeStamp:         timestamp,
			TaskHash:          taskHash,
			CmdPath:           cmdPath,
			PathName:          pathName,
			Dev:               dev,
			Inode:             inode,
			Ctime:             ctime,
			InodeMode:         inodeMode,
			InterPathName:     interPathName,
			InterDev:          interDev,
			InterInode:        interInode,
			InterCtime:        interCtime,
			Interpreter:       interpreter,
			StdinType:         stdinType,
			StdinPath:         stdinPath,
			InvokedFromKernel: invokedFromKernel,
		},
	)
}

func (ctrl *Controller) processSchedProcessExit(args []trace.Argument) error {
	paramsLength := len(events.Core.GetDefinitionByID(events.SignalSchedProcessExit).GetParams())
	if len(args) != paramsLength {
		return errfmt.Errorf("got %d args instead of %d", len(args), paramsLength)
	}

	taskHash, err := parse.ArgVal[uint32](args, "task_hash")
	if err != nil {
		return errfmt.Errorf("error parsing task_hash: %v", err)
	}
	exitCode, err := parse.ArgVal[int64](args, "exit_code")
	if err != nil {
		return errfmt.Errorf("error parsing exit_code: %v", err)
	}
	exitTime, err := parse.ArgVal[uint64](args, "exit_time")
	if err != nil {
		return errfmt.Errorf("error parsing exit_time: %v", err)
	}
	groupExit, err := parse.ArgVal[bool](args, "process_group_exit")
	if err != nil {
		return errfmt.Errorf("error parsing process_group_exit: %v", err)
	}

	return ctrl.processTree.FeedFromExit(
		proctree.ExitFeed{
			TimeStamp: exitTime, // time of exit is already a timestamp
			TaskHash:  taskHash,
			ExitCode:  exitCode,
			ExitTime:  exitTime,
			Group:     groupExit,
		},
	)
}

package ebpf

import (
	"fmt"

	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/proctree"
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

	// NOTE: The "parent" related arguments can be ignored for process tree purposes.

	// Parent Process (Go up in hierarchy until parent is a process and not a lwp)
	parentTid, err := parse.ArgVal[int32](event.Args, "parent_process_tid")
	if err != nil {
		return err
	}
	parentNsTid, err := parse.ArgVal[int32](event.Args, "parent_process_ns_tid")
	if err != nil {
		return err
	}
	parentPid, err := parse.ArgVal[int32](event.Args, "parent_process_pid")
	if err != nil {
		return err
	}
	parentNsPid, err := parse.ArgVal[int32](event.Args, "parent_process_ns_pid")
	if err != nil {
		return err
	}
	parentStartTime, err := parse.ArgVal[uint64](event.Args, "parent_process_start_time")
	if err != nil {
		return err
	}

	// Thread Group Leader (might be the same as the "child", if "child" is a process)
	leaderTid, err := parse.ArgVal[int32](event.Args, "leader_tid")
	if err != nil {
		return err
	}
	leaderNsTid, err := parse.ArgVal[int32](event.Args, "leader_ns_tid")
	if err != nil {
		return err
	}
	leaderPid, err := parse.ArgVal[int32](event.Args, "leader_pid")
	if err != nil {
		return err
	}
	leaderNsPid, err := parse.ArgVal[int32](event.Args, "leader_ns_pid")
	if err != nil {
		return err
	}
	leaderStartTime, err := parse.ArgVal[uint64](event.Args, "leader_start_time")
	if err != nil {
		return err
	}

	// Child (might be a process or a thread)
	childTid, err := parse.ArgVal[int32](event.Args, "child_tid")
	if err != nil {
		return err
	}
	childNsTid, err := parse.ArgVal[int32](event.Args, "child_ns_tid")
	if err != nil {
		return err
	}
	childPid, err := parse.ArgVal[int32](event.Args, "child_pid")
	if err != nil {
		return err
	}
	childNsPid, err := parse.ArgVal[int32](event.Args, "child_ns_pid")
	if err != nil {
		return err
	}
	childStartTime, err := parse.ArgVal[uint64](event.Args, "start_time") // child_start_time
	if err != nil {
		return err
	}

	// Calculate hashes
	parentHash := utils.HashTaskID(uint32(parentTid), uint64(parentStartTime))
	leaderHash := utils.HashTaskID(uint32(leaderTid), uint64(leaderStartTime))
	childHash := utils.HashTaskID(uint32(childTid), uint64(childStartTime))

	return t.processTree.FeedFromFork(
		proctree.ForkFeed{
			TimeStamp:       childStartTime, // event timestamp is the same
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

// procTreeExecProcessor handles process exec events.
func (t *Tracee) procTreeExecProcessor(event *trace.Event) error {
	if t.processTree == nil {
		return fmt.Errorf("process tree is disabled")
	}
	if event.HostProcessID != event.HostThreadID {
		return nil // chek FeedFromExec for TODO of execve() handled by threads
	}

	// Executable
	cmdPath, err := parse.ArgVal[string](event.Args, "cmdpath")
	if err != nil {
		return err
	}
	pathName, err := parse.ArgVal[string](event.Args, "pathname")
	if err != nil {
		return err
	}
	dev, err := parse.ArgVal[uint32](event.Args, "dev")
	if err != nil {
		return err
	}
	inode, err := parse.ArgVal[uint64](event.Args, "inode")
	if err != nil {
		return err
	}
	ctime, err := parse.ArgVal[uint64](event.Args, "ctime")
	if err != nil {
		return err
	}
	inodeMode, err := parse.ArgVal[uint16](event.Args, "inode_mode")
	if err != nil {
		return err
	}

	// // Binary Interpreter (or Loader): might come empty from the kernel
	// interPathName, _ := parse.ArgVal[string](event.Args, "interpreter_pathname")
	// interDev, _ := parse.ArgVal[uint32](event.Args, "interpreter_dev")
	// interInode, _ := parse.ArgVal[uint64](event.Args, "interpreter_inode")
	// interCtime, _ := parse.ArgVal[uint64](event.Args, "interpreter_ctime")

	// Real Interpreter
	interp, err := parse.ArgVal[string](event.Args, "interp")
	if err != nil {
		return err
	}

	// Others
	stdinType, err := parse.ArgVal[uint16](event.Args, "stdin_type")
	if err != nil {
		return err
	}
	stdinPath, err := parse.ArgVal[string](event.Args, "stdin_path")
	if err != nil {
		return err
	}
	invokedFromKernel, err := parse.ArgVal[int32](event.Args, "invoked_from_kernel")
	if err != nil {
		return err
	}

	timestamp := uint64(event.Timestamp)
	taskHash := utils.HashTaskID(uint32(event.HostThreadID), uint64(event.ThreadStartTime))

	return t.processTree.FeedFromExec(
		proctree.ExecFeed{
			TimeStamp:  timestamp,
			TaskHash:   taskHash,
			ParentHash: 0, // regular pipeline does not have parent hash
			LeaderHash: 0, // regular pipeline does not have leader hash
			CmdPath:    cmdPath,
			PathName:   pathName,
			Dev:        dev,
			Inode:      inode,
			Ctime:      ctime,
			InodeMode:  inodeMode,
			// InterpreterPath:   interPathName,
			// InterpreterDev:    interDev,
			// InterpreterInode:  interInode,
			// InterpreterCtime:  interCtime,
			Interp:            interp,
			StdinType:         stdinType,
			StdinPath:         stdinPath,
			InvokedFromKernel: invokedFromKernel,
		},
	)
}

// procTreeExitProcessor handles process exit events.
func (t *Tracee) procTreeExitProcessor(event *trace.Event) error {
	if t.processTree == nil {
		return fmt.Errorf("process tree is disabled")
	}
	if event.HostProcessID != event.HostThreadID {
		return nil // chek FeedFromExec for TODO of execve() handled by threads
	}

	// Exit logic arguments
	exitCode, err := parse.ArgVal[int64](event.Args, "exit_code")
	if err != nil {
		return err
	}
	groupExit, err := parse.ArgVal[bool](event.Args, "process_group_exit")
	if err != nil {
		return err
	}

	timestamp := uint64(event.Timestamp)
	taskHash := utils.HashTaskID(uint32(event.HostThreadID), uint64(event.ThreadStartTime))

	return t.processTree.FeedFromExit(
		proctree.ExitFeed{
			TimeStamp:  timestamp, // time of exit is already a timestamp
			TaskHash:   taskHash,
			ParentHash: 0, // regular pipeline does not have parent hash
			LeaderHash: 0, // regular pipeline does not have leader hash
			ExitCode:   exitCode,
			Group:      groupExit,
		},
	)
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

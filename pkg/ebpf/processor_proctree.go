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
	var errs []error

	if t.processTree == nil {
		return fmt.Errorf("process tree is disabled")
	}

	// NOTE: The "parent" related arguments can be ignored for process tree purposes.

	// Parent Process (Go up in hierarchy until parent is a process and not a lwp)
	parentTid, err := parse.ArgVal[int32](event.Args, "parent_process_tid")
	errs = append(errs, err)
	parentNsTid, err := parse.ArgVal[int32](event.Args, "parent_process_ns_tid")
	errs = append(errs, err)
	parentPid, err := parse.ArgVal[int32](event.Args, "parent_process_pid")
	errs = append(errs, err)
	parentNsPid, err := parse.ArgVal[int32](event.Args, "parent_process_ns_pid")
	errs = append(errs, err)
	parentStartTime, err := parse.ArgVal[uint64](event.Args, "parent_process_start_time")
	errs = append(errs, err)

	// Thread Group Leader (might be the same as the "child", if "child" is a process)
	leaderTid, err := parse.ArgVal[int32](event.Args, "leader_tid")
	errs = append(errs, err)
	leaderNsTid, err := parse.ArgVal[int32](event.Args, "leader_ns_tid")
	errs = append(errs, err)
	leaderPid, err := parse.ArgVal[int32](event.Args, "leader_pid")
	errs = append(errs, err)
	leaderNsPid, err := parse.ArgVal[int32](event.Args, "leader_ns_pid")
	errs = append(errs, err)
	leaderStartTime, err := parse.ArgVal[uint64](event.Args, "leader_start_time")
	errs = append(errs, err)

	// Child (might be a process or a thread)
	childTid, err := parse.ArgVal[int32](event.Args, "child_tid")
	errs = append(errs, err)
	childNsTid, err := parse.ArgVal[int32](event.Args, "child_ns_tid")
	errs = append(errs, err)
	childPid, err := parse.ArgVal[int32](event.Args, "child_pid")
	errs = append(errs, err)
	childNsPid, err := parse.ArgVal[int32](event.Args, "child_ns_pid")
	errs = append(errs, err)
	childStartTime, err := parse.ArgVal[uint64](event.Args, "start_time") // child_start_time
	errs = append(errs, err)

	// Deal with errors
	for _, err := range errs {
		if err != nil {
			return err
		}
	}

	// Calculate hashes
	childHash := utils.HashTaskID(uint32(childTid), uint64(childStartTime))
	parentHash := utils.HashTaskID(uint32(parentTid), uint64(parentStartTime))
	leaderHash := utils.HashTaskID(uint32(leaderTid), uint64(leaderStartTime))

	return t.processTree.FeedFromFork(
		proctree.ForkFeed{
			TimeStamp:       uint64(t.timeNormalizer.NormalizeTime(int(childStartTime))), // event timestamp is the same
			ChildHash:       childHash,
			ParentHash:      parentHash,
			LeaderHash:      leaderHash,
			ParentTid:       parentTid,
			ParentNsTid:     parentNsTid,
			ParentPid:       parentPid,
			ParentNsPid:     parentNsPid,
			ParentStartTime: uint64(t.timeNormalizer.NormalizeTime(int(parentStartTime))),
			LeaderTid:       leaderTid,
			LeaderNsTid:     leaderNsTid,
			LeaderPid:       leaderPid,
			LeaderNsPid:     leaderNsPid,
			LeaderStartTime: uint64(t.timeNormalizer.NormalizeTime(int(leaderStartTime))),
			ChildTid:        childTid,
			ChildNsTid:      childNsTid,
			ChildPid:        childPid,
			ChildNsPid:      childNsPid,
			ChildStartTime:  uint64(t.timeNormalizer.NormalizeTime(int(childStartTime))),
		},
	)
}

// procTreeExecProcessor handles process exec events.
func (t *Tracee) procTreeExecProcessor(event *trace.Event) error {
	var errs []error

	if t.processTree == nil {
		return fmt.Errorf("process tree is disabled")
	}
	if event.HostProcessID != event.HostThreadID {
		return nil // chek FeedFromExec for TODO of execve() handled by threads
	}

	timestamp := uint64(event.Timestamp)
	taskHash := utils.HashTaskID(uint32(event.HostThreadID), uint64(event.ThreadStartTime))

	// Executable
	cmdPath, err := parse.ArgVal[string](event.Args, "cmdpath")
	errs = append(errs, err)
	pathName, err := parse.ArgVal[string](event.Args, "pathname")
	errs = append(errs, err)
	dev, err := parse.ArgVal[uint32](event.Args, "dev")
	errs = append(errs, err)
	inode, err := parse.ArgVal[uint64](event.Args, "inode")
	errs = append(errs, err)
	ctime, err := parse.ArgVal[uint64](event.Args, "ctime")
	errs = append(errs, err)
	inodeMode, err := parse.ArgVal[uint16](event.Args, "inode_mode")
	errs = append(errs, err)

	// Binary Interpreter (or Loader): might come empty from the kernel
	interPathName, _ := parse.ArgVal[string](event.Args, "interpreter_pathname")
	interDev, _ := parse.ArgVal[uint32](event.Args, "interpreter_dev")
	interInode, _ := parse.ArgVal[uint64](event.Args, "interpreter_inode")
	interCtime, _ := parse.ArgVal[uint64](event.Args, "interpreter_ctime")

	// Real Interpreter
	interp, err := parse.ArgVal[string](event.Args, "interp")
	errs = append(errs, err)

	// Others
	stdinType, err := parse.ArgVal[uint16](event.Args, "stdin_type")
	errs = append(errs, err)
	stdinPath, err := parse.ArgVal[string](event.Args, "stdin_path")
	errs = append(errs, err)
	invokedFromKernel, err := parse.ArgVal[int32](event.Args, "invoked_from_kernel")
	errs = append(errs, err)

	// Handle errors
	for _, err := range errs {
		if err != nil {
			return err
		}
	}

	return t.processTree.FeedFromExec(
		proctree.ExecFeed{
			TimeStamp:         uint64(t.timeNormalizer.NormalizeTime(int(timestamp))),
			TaskHash:          taskHash,
			ParentHash:        0, // regular pipeline does not have parent hash
			LeaderHash:        0, // regular pipeline does not have leader hash
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

// procTreeExitProcessor handles process exit events.
func (t *Tracee) procTreeExitProcessor(event *trace.Event) error {
	var errs []error

	if t.processTree == nil {
		return fmt.Errorf("process tree is disabled")
	}
	if event.HostProcessID != event.HostThreadID {
		return nil // chek FeedFromExec for TODO of execve() handled by threads
	}

	timestamp := uint64(event.Timestamp)
	taskHash := utils.HashTaskID(uint32(event.HostThreadID), uint64(event.ThreadStartTime))

	// Exit logic arguments
	exitCode, err := parse.ArgVal[int64](event.Args, "exit_code")
	errs = append(errs, err)
	groupExit, err := parse.ArgVal[bool](event.Args, "process_group_exit")
	errs = append(errs, err)

	// Handle errors
	for _, err := range errs {
		if err != nil {
			return err
		}
	}

	return t.processTree.FeedFromExit(
		proctree.ExitFeed{
			TimeStamp:  uint64(t.timeNormalizer.NormalizeTime(int(timestamp))), // time of exit is already a timestamp
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
	eventTimestamp := traceetime.NsSinceEpochToTime(uint64(t.timeNormalizer.NormalizeTime(event.Timestamp)))

	executable := currentProcess.GetExecutable()

	// Update the event with the executable information from the process tree.
	event.Executable.Path = executable.GetPathAt(eventTimestamp)

	// TODO: feed executable information from procfs during proctree initialization.

	return nil
}

package controlplane

import (
	"fmt"
	"os"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/aquasecurity/tracee/types/trace"
)

//
// Processes Lifecycle
//

func (p *Controller) processSchedProcessFork(args []trace.Argument) error {
	var file *os.File

	if len(args) != 12 {
		return errfmt.Errorf("got %d args instead of %d", len(args), 12)
	}

	taskHash, err := parse.ArgVal[uint32](args, "task_hash")
	if err != nil {
		return errfmt.Errorf("error parsing task_hash: %v", err)
	}
	parentHash, err := parse.ArgVal[uint32](args, "parent_hash")
	if err != nil {
		return errfmt.Errorf("error parsing parent_hash: %v", err)
	}

	// Parent

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

	// Child

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

	taskHashVerifier := utils.HashU32AndU64(uint32(childTid), childStartTime)
	parentHashVerifier := utils.HashU32AndU64(uint32(parentTid), parentStartTime)

	if taskHash != taskHashVerifier || parentHash != parentHashVerifier {
		return errfmt.Errorf("eBPF Hash does not match")
	}

	// if childTid != childPid {
	// DEBUG (remove only when process tree is implemented)
	file, _ = os.Open("/dev/null")
	defer func() {
		_ = file.Close()
	}()
	// file = os.Stdout
	fmt.Fprintf(file, "--\nFork event received:\n")
	fmt.Fprintf(file, "Parent Hash: %v (Verifier: %v)\n", parentHash, parentHashVerifier)
	fmt.Fprintf(file, "Parent: tid=%v ns_tid=%v pid=%v ns_pid=%v start_time=%v\n", parentTid, parentNsTid, parentPid, parentNsPid, parentStartTime)
	fmt.Fprintf(file, "Task Hash: %v (Verifier: %d)\n", taskHash, taskHashVerifier)
	fmt.Fprintf(file, "Child: tid=%v ns_tid=%v pid=%v ns_pid=%v start_time=%v\n", childTid, childNsTid, childPid, childNsPid, childStartTime)
	// END OF DEBUG
	// }

	return nil
}

func (p *Controller) processSchedProcessExec(args []trace.Argument) error {
	var file *os.File

	if len(args) != 16 {
		return errfmt.Errorf("got %d args instead of %d", len(args), 16)
	}

	taskHash, err := parse.ArgVal[uint32](args, "task_hash")
	if err != nil {
		return errfmt.Errorf("error parsing task_hash: %v", err)
	}

	// command

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

	// interpreter

	interPathName, err := parse.ArgVal[string](args, "interpreter_pathname")
	if err != nil {
		return errfmt.Errorf("error parsing interpreter_pathname: %v", err)
	}
	interDev, err := parse.ArgVal[uint32](args, "interpreter_dev")
	if err != nil {
		return errfmt.Errorf("error parsing interpreter_dev: %v", err)
	}
	interInode, err := parse.ArgVal[uint64](args, "interpreter_inode")
	if err != nil {
		return errfmt.Errorf("error parsing interpreter_inode: %v", err)
	}
	interCtime, err := parse.ArgVal[uint64](args, "interpreter_ctime")
	if err != nil {
		return errfmt.Errorf("error parsing interpreter_ctime: %v", err)
	}
	interpreter, err := parse.ArgVal[string](args, "interp")
	if err != nil {
		return errfmt.Errorf("error parsing interp: %v", err)
	}

	// stdin

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

	// DEBUG (remove only when process tree is implemented)
	file, _ = os.Open("/dev/null")
	defer func() {
		_ = file.Close()
	}()
	// file = os.Stdout
	fmt.Fprintf(file, "--\nExec event received:\n")
	fmt.Fprintf(file, "taskHash=%v\n", taskHash)
	fmt.Fprintf(file, "cmdPath=%v\n", cmdPath)
	fmt.Fprintf(file, "pathName=%v\n", pathName)
	fmt.Fprintf(file, "interPathName=%v\n", interPathName)
	fmt.Fprintf(file, "interpreter=%v\n", interpreter)
	fmt.Fprintf(file, "stdinPath=%v\n", stdinPath)
	fmt.Fprintf(file, "dev=%v\n", dev)
	fmt.Fprintf(file, "interDev=%v\n", interDev)
	fmt.Fprintf(file, "inode=%v\n", inode)
	fmt.Fprintf(file, "ctime=%v\n", ctime)
	fmt.Fprintf(file, "interInode=%v\n", interInode)
	fmt.Fprintf(file, "interCtime=%v\n", interCtime)
	fmt.Fprintf(file, "inodeMode=%v\n", inodeMode)
	fmt.Fprintf(file, "stdinType=%v\n", stdinType)
	fmt.Fprintf(file, "invokedFromKernel=%v\n", invokedFromKernel)
	// END OF DEBUG

	return nil
}

func (p *Controller) processSchedProcessExit(args []trace.Argument) error {
	var file *os.File

	if len(args) != 4 {
		return errfmt.Errorf("got %d args instead of %d", len(args), 4)
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

	// DEBUG (remove only when process tree is implemented)
	file, _ = os.Open("/dev/null")
	defer func() {
		_ = file.Close()
	}()
	// file = os.Stdout
	fmt.Fprintf(file, "--\nExit event received:\n")
	fmt.Fprintf(file, "taskHash=%v\n", taskHash)
	fmt.Fprintf(file, "exitCode=%d\n", exitCode)
	fmt.Fprintf(file, "groupExit=%t\n", groupExit)
	fmt.Fprintf(file, "exitTime=%d\n", exitTime)
	// END OF DEBUG

	return nil
}

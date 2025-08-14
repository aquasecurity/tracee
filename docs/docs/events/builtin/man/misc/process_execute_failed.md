---
title: TRACEE-PROCESS-EXECUTE-FAILED
section: 1
header: Tracee Event Manual
---

## NAME

**process_execute_failed** - a failed process execution occurred

## DESCRIPTION

A high-level event that captures process execution failures, providing detailed information about the failed execution attempt including the binary path, interpreter details, and execution context. This event aims to encompass all failure cases of process execution while providing kernel-level execution arguments.

The event provides comprehensive visibility into execution failures, which is crucial for debugging application issues, detecting security problems, and monitoring system behavior. It captures both user-space and kernel-initiated execution attempts.

This event is useful for:

- **Execution debugging**: Track and analyze process execution failures
- **Security monitoring**: Detect failed execution attempts that might indicate attacks
- **System diagnostics**: Understand process execution issues
- **Permission analysis**: Monitor access control failures

## EVENT SETS

**none**

## DATA FIELDS

**path** (*string*)
: The path to the file as provided by the user

**binary** (*object*)
: Binary execution details containing:
  - **path** (*string*): The binary path being executed
  - **device_id** (*uint32*): The device ID of the binary
  - **inode_number** (*uint64*): The inode number of the binary
  - **ctime** (*uint64*): The change time of the binary
  - **inode_mode** (*uint64*): The inode mode of the binary

**interpreter_path** (*string*)
: The path to the interpreter used

**stdin_type** (*uint16*)
: The stdin type

**stdin_path** (*string*)
: The stdin path

**kernel_invoked** (*bool*)
: Whether this execution was initiated by the kernel

**environment** (*[]string*)
: The environment variables of this execution

**arguments** (*[]string*)
: The arguments of this execution

## DEPENDENCIES

**Kernel Version >= 5.8:**

- security_bprm_creds_for_exec (kprobe, required): Retrieve execution arguments
- sys_enter (tracepoint, required): Obtain execution return code

**Kernel Version < 5.8:**

- exec_binprm (kprobe + kretprobe, required): Retrieve execution arguments and return value

## USE CASES

- **Application debugging**: Identify why process executions are failing

- **Security monitoring**: Detect unauthorized execution attempts

- **System diagnostics**: Track execution failures for system health

- **Permission analysis**: Monitor access control and capability issues

- **Configuration validation**: Verify execution environment setup

## KERNEL VERSION CONSIDERATIONS

The event behavior varies by kernel version:

**Kernel >= 5.8:**
- Uses security_bprm_creds_for_exec hook
- More comprehensive failure detection
- Better execution context information

**Kernel < 5.8:**
- Uses exec_binprm hook
- Limited to failures within exec_binprm
- May miss early-stage failures

## LIMITATIONS

- **Kernel < 5.8**: May miss failures occurring before exec_binprm
- **Kernel >= 5.8**: May miss failures before security_bprm_creds_for_exec
- **exec_binprm symbol**: May not be available in some systems
- **TOCTOU**: Environment and arguments subject to race conditions

## RELATED EVENTS

- **execve**: Process execution system call
- **execveat**: Extended process execution system call
- **bprm_check**: Binary format preparation check
- **sched_process_exec**: Successful process execution events

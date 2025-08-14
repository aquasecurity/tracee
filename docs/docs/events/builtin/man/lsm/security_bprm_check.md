---
title: TRACEE-SECURITY-BPRM-CHECK
section: 1
header: Tracee Event Manual
---

## NAME

**security_bprm_check** - verify permissions prior to binary handler search

## DESCRIPTION

Triggered during the execution of a binary via execve or execveat, just before the kernel begins searching for the specific binary handler. This LSM (Linux Security Module) hook event occurs at a critical point where new process attributes are being set but the context is still that of the pre-execution process.

This event is particularly valuable when the pre-execution context is significant, as it provides resolved path and binary details. While it offers less comprehensive information than sched_process_exec, it captures the execution state at a unique point in the process lifecycle.

This event is useful for:

- **Permission verification**: Monitor execution permission checks
- **Binary execution tracking**: Track program execution with resolved paths
- **Pre-execution analysis**: Examine process state before context change
- **Security monitoring**: Verify execution permissions and context

## EVENT SETS

**none**

## DATA FIELDS

**pathname** (*string*)
: The resolved path of the file being executed

**dev** (*uint32*)
: The device identifier of the executed file

**inode** (*uint64*)
: The inode number of the executed file

**argv** (*[]string*)
: The arguments provided during execution

**envp** (*[]string*)
: The environment variables passed during execution (optional, filled only if requested)

## DEPENDENCIES

**LSM Hook:**

- security_bprm_check (required): LSM hook for execution phase before context change

**Tracepoint:**

- sys_enter (required): Used to capture argv from syscall arguments

## USE CASES

- **Security monitoring**: Verify execution permissions and context

- **Binary tracking**: Monitor program execution with resolved paths

- **Context analysis**: Examine process state before execution

- **Permission auditing**: Track execution permission checks

- **Environment monitoring**: Analyze execution context and variables

## EXECUTION CONTEXT

The event captures the execution state at a unique point:

- **Pre-handler search**: Before binary format handler selection
- **Pre-context change**: Original process context still available
- **Post-path resolution**: Full path information available
- **Pre-execution**: Before actual program loading

## SECURITY CONSIDERATIONS

Important security aspects to monitor:

- **Permission verification**: Check execution permissions
- **Path resolution**: Track resolved binary paths
- **Environment inspection**: Monitor execution context
- **Argument validation**: Check execution parameters
- **TOCTOU concerns**: Be aware of potential race conditions

## LIMITATIONS

- **TOCTOU**: Arguments and environment subject to race conditions
- **Partial information**: Less comprehensive than sched_process_exec
- **Optional data**: Environment variables only if configured
- **Pre-execution only**: No information about actual execution success

## RELATED EVENTS

- **sched_process_exec**: Process execution after context change
- **execve**: System call for executing programs
- **execveat**: Extended program execution system call

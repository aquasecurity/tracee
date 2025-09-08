---
title: TRACEE-SCHED-PROCESS-EXEC
section: 1
header: Tracee Event Manual
---

## NAME

**sched_process_exec** - process execution scheduler event

## DESCRIPTION

Triggered when a new process is executed, capturing detailed information about the executed process through the kernel's scheduler tracepoint. This event provides comprehensive process execution details including binary information, interpreter details, arguments, environment variables, and execution context.

This is a kernel-level tracepoint that fires whenever the scheduler handles process execution, providing more detailed information than the basic `execve` system call. It's particularly useful for understanding the complete execution context and metadata about executed programs.

## EVENT SETS

**none**

## DATA FIELDS

**cmdpath** (*string*)
: The path of the command being executed

**pathname** (*string*)
: Path to the executable binary

**dev** (*uint32*)
: Device number associated with the executable

**inode** (*uint64*)
: Inode number of the executable

**ctime** (*uint64*)
: Creation time of the executable

**inode_mode** (*uint16*)
: Mode of the inode for the executable (permissions and file type)

**interpreter_pathname** (*string*)
: Path of the interpreter for the executable (if applicable)

**interpreter_dev** (*uint32*)
: Device number associated with the interpreter

**interpreter_inode** (*uint64*)
: Inode number of the interpreter

**interpreter_ctime** (*uint64*)
: Creation time of the interpreter

**argv** (*[]string*)
: Array of arguments passed to the binary during execution

**interp** (*string*)
: Specifies the interpreter of the binary (from shebang line)

**stdin_type** (*uint16*)
: Mode of the standard input (file type and permissions)

**stdin_path** (*string*)
: Path of the standard input source

**invoked_from_kernel** (*bool*)
: Flag indicating if the process was initiated by the kernel

**env** (*[]string*)
: Environment variables associated with the process

## DEPENDENCIES

**Kernel Tracepoint:**

- sched_process_exec (required): Raw tracepoint in the kernel scheduler

## USE CASES

- **Security monitoring**: Comprehensive tracking of process execution with metadata

- **Digital forensics**: Detailed process execution analysis with file system context

- **Compliance auditing**: Complete audit trail of executed programs and their context

- **Malware analysis**: Understanding execution patterns and binary characteristics

- **Performance analysis**: Monitoring process creation overhead and patterns

## EXECUTION CONTEXT

This event captures execution at the scheduler level, providing:

**Binary Information:**
- Complete file system metadata (device, inode, timestamps)
- File permissions and type information
- Path resolution and location details

**Interpreter Details:**
- Script interpreter information from shebang lines
- Interpreter binary metadata and location
- Multi-level interpretation chains

**Execution Environment:**
- Complete command line arguments
- Full environment variable set
- Standard I/O configuration and sources

## KERNEL VS USER EXECUTION

The `invoked_from_kernel` field distinguishes between:

**Kernel-initiated processes:**
- Kernel threads and workers
- System-initiated tasks and helpers
- Device drivers and subsystem processes

**User-initiated processes:**
- User commands and applications
- Shell-launched programs
- Application-spawned child processes

## INTERPRETER HANDLING

Special handling for interpreted programs:

**Script Execution:**
- Shebang (#!) line parsing and interpreter identification
- Interpreter binary location and metadata
- Script vs binary execution distinction

**Dynamic Linking:**
- Dynamic linker/loader information
- Shared library resolution context
- Runtime loading characteristics

## STDIN ANALYSIS

Standard input source tracking:

**Input Types:**
- Terminal/TTY input for interactive programs
- File redirection sources
- Pipe and socket input sources
- Device input (e.g., /dev/null, /dev/zero)

## PERFORMANCE CONSIDERATIONS

This event provides extensive information but may impact performance:

**High Overhead Scenarios:**
- Systems with frequent process creation
- Container environments with many short-lived processes
- Build systems and CI/CD pipelines

**Optimization Strategies:**
- Filter by specific processes or paths when possible
- Use sampling for high-frequency environments
- Consider selective field collection

## SECURITY ANALYSIS

Rich context enables sophisticated security analysis:

**Anomaly Detection:**
- Unusual execution patterns or locations
- Unexpected interpreter usage
- Abnormal argument or environment patterns

**Threat Hunting:**
- Malware execution characteristics
- Living-off-the-land technique detection
- Supply chain compromise indicators

## RELATED EVENTS

- **execve**: System call level process execution
- **sched_process_fork**: Process creation scheduler event
- **sched_process_exit**: Process termination scheduler event
- **security_bprm_check**: LSM hook for executable security validation
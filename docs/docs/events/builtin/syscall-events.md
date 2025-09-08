# Syscalls

Tracee provides two approaches for monitoring Linux system calls:

## Specific Syscall Monitoring

Each system call is available as an individual event with the same name as the syscall. For example, to trace the `open` system call, use the `open` event name. These events use dedicated kprobes for targeted, efficient monitoring of specific syscalls.

The arguments of the system call are automatically captured as event data fields, with types properly mapped from kernel types to Go types (e.g., `const char*` becomes `string`).

## Comprehensive Syscall Monitoring

For broad syscall analysis, Tracee provides comprehensive monitoring events:

- **sys_enter**: Captures all system call entries using raw tracepoints
- **sys_exit**: Captures all system call exits using raw tracepoints

These events are ideal for:
- Security auditing across all syscalls
- System-wide syscall pattern analysis
- Performance monitoring of syscall frequency
- Detecting anomalous syscall behavior

**Note**: These comprehensive events generate high volumes of data since they capture every syscall. Use filtering or sampling for production environments.

For detailed documentation about any specific system call, including its purpose, arguments, return values, and error conditions, please consult the standard Linux manual pages (man section 2). These can be accessed via:

- `man 2 syscall_name` (e.g., `man 2 open`)
- Online at [man7.org](https://man7.org/linux/man-pages/dir_section_2.html)

## Event Sets

All syscall events automatically belong to the **syscalls** set. Many syscalls also belong to additional sets based on their functionality:

- **fs**: File system operations (e.g., open, read, write)
- **net**: Network operations (e.g., socket, connect, bind)
- **proc**: Process operations (e.g., fork, execve, exit)
- **ipc**: Inter-process communication (e.g., pipe, mmap)
- **time**: Time-related operations (e.g., clock_gettime)
- **signals**: Signal handling (e.g., kill, sigaction)

## Examples

Tracing specific syscalls:
```bash
# Trace file opens
tracee -e open

# Trace process creation
tracee -e execve,fork,clone

# Trace network connections
tracee -e socket,connect,bind,accept
```

## Notes

- Event data fields use Go types (string, uint32, etc.)
- Some syscalls may have architecture-specific variants
- Some syscalls may be deprecated or not available on all systems
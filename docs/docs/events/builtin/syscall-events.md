# Syscalls

Tracee supports tracing all Linux system calls. Each system call is available as an event with the same name as the syscall. For example, to trace the `open` system call, use the `open` event name.

The arguments of the system call are automatically captured as event data fields, with types properly mapped from kernel types to Go types (e.g., `const char*` becomes `string`).

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
# Syscalls

Tracee supports tracing all Linux system calls. To trace a system call, use it's name as the event name. For example, to trace the `open` system call, use the `open` event name. The arguments of the system call will be available as event arguments. For more information about system calls, please consult the [man pages](https://man7.org/linux/man-pages/dir_section_2.html).

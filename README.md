# contracer
Container tracing using eBPF

Currently requires kernel version 4.14-4.18

## Usage

As root: `./start.py -v`

## TODO

* Add support for kernel versions 4.19 onwards
* Add envp to execve(at) syscalls. Put argv and envp in a list instead being different param for each arg
* Add full sockaddr struct fields to: "connect", "accept", "bind", "getsockname"
* Consider tracing commit_creds to detect potential kernel exploits
* Fix missing pathname in execveat syscall
* Add check for head and tail to avoid overflow in the submission buffer
* Change submission_buf size from 32 to num_of_cpu which can be determined by userspace and set accordingly
* Consider re-writing userspace side (python) in golang
* Allow user to enable/disable events from cmd line
* Reduce number of missing events by optimizing event_t to use 4 bytes (sent by perf_submit)

## Known Issues

* Pathname is missing in execveat syscall
* Missing events when event rate is high

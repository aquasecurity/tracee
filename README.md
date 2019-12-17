# Tracee
Container and system tracing using eBPF

**Tracee** is a lightweight, easy to use container and system tracing tool.
After launching the tool, it will start collecting traces of newly created containers (container mode) or processes (system mode).
The collected traces are mostly system calls performed by the processes,
but other events, such as capabilities required to perform the actions requested by the process, are also supported.

## Requirements
Currently requires 
* kernel version 4.14-4.18
* BCC

## Quick Start Instructions

As root: `start.py [-h] [-c] [--max-args MAX_ARGS] [-j] [-e EVENTS_TO_TRACE]`

optional arguments:

-h, --help            show this help message and exit

-c, --container       only trace newly created containers

--max-args MAX_ARGS   maximum number of arguments parsed and displayed, defaults to 20

-j, --json            save events in json format

-l, --list            list events

-e EVENTS_TO_TRACE, --events-to-trace EVENTS_TO_TRACE
trace only the specified events and syscalls (default: trace all)

examples:

`./start.py -c`

Following is an output example of Tracee after running

`docker run -it --rm alpine sh`

```
TIME(s)        UTS_NAME         MNT_NS       PID_NS       UID    EVENT            COMM             PID    TID    PPID   RET          ARGS
61193.235110   e89fcd33936c     4026532402   4026532405   0      execve           runc:[2:INIT]    1      1      13670  0            /bin/sh
61193.235178   e89fcd33936c     4026532402   4026532405   0      cap_capable      runc:[2:INIT]    1      1      13670  0            CAP_SYS_ADMIN
61193.235207   e89fcd33936c     4026532402   4026532405   0      do_exit          runc:[2:INIT]    1      4      13670  0            
61193.235206   e89fcd33936c     4026532402   4026532405   0      do_exit          runc:[2:INIT]    1      2      13670  0            
61193.235207   e89fcd33936c     4026532402   4026532405   0      do_exit          runc:[2:INIT]    1      5      13670  0            
61193.235206   e89fcd33936c     4026532402   4026532405   0      do_exit          runc:[2:INIT]    1      3      13670  0            
61193.235873   e89fcd33936c     4026532402   4026532405   0      mprotect         sh               1      1      13670  0            0x7f9e08f39000 4096 1
61193.235951   e89fcd33936c     4026532402   4026532405   0      mprotect         sh               1      1      13670  0            0x555e7ad57000 16384 1
61193.236050   e89fcd33936c     4026532402   4026532405   0      ioctl            sh               1      1      13670  0            0 21523
61193.236062   e89fcd33936c     4026532402   4026532405   0      ioctl            sh               1      1      13670  0            1 21523
61193.236088   e89fcd33936c     4026532402   4026532405   0      open             sh               1      1      13670  3            /dev/tty O_RDWR
61193.236105   e89fcd33936c     4026532402   4026532405   0      close            sh               1      1      13670  0            3
61193.236121   e89fcd33936c     4026532402   4026532405   0      ioctl            sh               1      1      13670  0            10 21519
61193.236142   e89fcd33936c     4026532402   4026532405   0      ioctl            sh               1      1      13670  0            10 21520
61193.236172   e89fcd33936c     4026532402   4026532405   0      stat             sh               1      1      13670  -2           MAILPATH
61193.236191   e89fcd33936c     4026532402   4026532405   0      ioctl            sh               1      1      13670  0            0 21505
61193.236214   e89fcd33936c     4026532402   4026532405   0      cap_capable      sh               1      1      13670  0            CAP_SYS_ADMIN
61193.236228   e89fcd33936c     4026532402   4026532405   0      open             sh               1      1      13670  -2           /root/.ash_history O_RDONLY
61193.236258   e89fcd33936c     4026532402   4026532405   0      ioctl            sh               1      1      13670  0            0 21506
61193.236277   e89fcd33936c     4026532402   4026532405   0      open             sh               1      1      13670  3            /etc/passwd O_RDONLY|O_CLOEXEC
61193.236300   e89fcd33936c     4026532402   4026532405   0      close            sh               1      1      13670  0            3
61193.236313   e89fcd33936c     4026532402   4026532405   0      ioctl            sh               1      1      13670  0            0 21523
61193.236334   e89fcd33936c     4026532402   4026532405   0      ioctl            sh               1      1      13670  0            1 21523
61193.256423   e89fcd33936c     4026532402   4026532405   0      ioctl            sh               1      1      13670  0            0 21523

```

Executing `ls` in the alpine container shell will trigger the following events:

```
61405.843786   e89fcd33936c     4026532402   4026532405   0      cap_capable      sh               1      1      13670  0            CAP_SYS_ADMIN
61405.843977   e89fcd33936c     4026532402   4026532405   0      cap_capable      sh               1      1      13670  0            CAP_DAC_READ_SEARCH
61405.844080   e89fcd33936c     4026532402   4026532405   0      cap_capable      sh               1      1      13670  0            CAP_DAC_OVERRIDE
61405.844284   e89fcd33936c     4026532402   4026532405   0      cap_capable      sh               1      1      13670  0            CAP_SYS_ADMIN
61405.844352   e89fcd33936c     4026532402   4026532405   0      cap_capable      sh               1      1      13670  0            CAP_DAC_OVERRIDE
61405.844520   e89fcd33936c     4026532402   4026532405   0      open             sh               1      1      13670  3            /root/.ash_history O_WRONLY|O_CREAT|O_APPEND
61405.844638   e89fcd33936c     4026532402   4026532405   0      close            sh               1      1      13670  0            3
61405.844709   e89fcd33936c     4026532402   4026532405   0      ioctl            sh               1      1      13670  0            0 21506
61405.844819   e89fcd33936c     4026532402   4026532405   0      stat             sh               1      1      13670  -2           /usr/local/sbin/ls
61405.844891   e89fcd33936c     4026532402   4026532405   0      stat             sh               1      1      13670  -2           /usr/local/bin/ls
61405.844951   e89fcd33936c     4026532402   4026532405   0      stat             sh               1      1      13670  -2           /usr/sbin/ls
61405.845009   e89fcd33936c     4026532402   4026532405   0      stat             sh               1      1      13670  -2           /usr/bin/ls
61405.845067   e89fcd33936c     4026532402   4026532405   0      stat             sh               1      1      13670  -2           /sbin/ls
61405.845141   e89fcd33936c     4026532402   4026532405   0      stat             sh               1      1      13670  0            /bin/ls
61405.845621   e89fcd33936c     4026532402   4026532405   0      fork             sh               1      1      13670  6            
61405.849460   e89fcd33936c     4026532402   4026532405   0      ioctl            sh               1      1      13670  0            10 21520
61405.849500   e89fcd33936c     4026532402   4026532405   0      stat             sh               1      1      13670  -2           MAILPATH
61405.849539   e89fcd33936c     4026532402   4026532405   0      ioctl            sh               1      1      13670  0            0 21505
61405.849562   e89fcd33936c     4026532402   4026532405   0      ioctl            sh               1      1      13670  0            0 21506
61405.849592   e89fcd33936c     4026532402   4026532405   0      open             sh               1      1      13670  3            /etc/passwd O_RDONLY|O_CLOEXEC
61405.849626   e89fcd33936c     4026532402   4026532405   0      close            sh               1      1      13670  0            3
61405.849646   e89fcd33936c     4026532402   4026532405   0      ioctl            sh               1      1      13670  0            0 21523
61405.845834   e89fcd33936c     4026532402   4026532405   0      ioctl            sh               6      6      1      0            10 21520
61405.845966   e89fcd33936c     4026532402   4026532405   0      execve           sh               6      6      1      0            /bin/ls
61405.846806   e89fcd33936c     4026532402   4026532405   0      mprotect         ls               6      6      1      0            0x7f45e179d000 4096 1
61405.847096   e89fcd33936c     4026532402   4026532405   0      mprotect         ls               6      6      1      0            0x555601b06000 16384 1
61405.847319   e89fcd33936c     4026532402   4026532405   0      ioctl            ls               6      6      1      0            0 21523
61405.847398   e89fcd33936c     4026532402   4026532405   0      ioctl            ls               6      6      1      0            1 21523
61405.847451   e89fcd33936c     4026532402   4026532405   0      ioctl            ls               6      6      1      0            1 21523
61405.847517   e89fcd33936c     4026532402   4026532405   0      stat             ls               6      6      1      0            .
61405.847595   e89fcd33936c     4026532402   4026532405   0      open             ls               6      6      1      3            . O_RDONLY|O_DIRECTORY|O_CLOEXEC
61405.847789   e89fcd33936c     4026532402   4026532405   0      getdents64       ls               6      6      1      496          3
61405.847891   e89fcd33936c     4026532402   4026532405   0      lstat            ls               6      6      1      0            ./sys
61405.847956   e89fcd33936c     4026532402   4026532405   0      lstat            ls               6      6      1      0            ./usr
61405.848015   e89fcd33936c     4026532402   4026532405   0      lstat            ls               6      6      1      0            ./sbin
61405.848097   e89fcd33936c     4026532402   4026532405   0      cap_capable      ls               6      6      1      0            CAP_SYS_ADMIN
61405.848167   e89fcd33936c     4026532402   4026532405   0      lstat            ls               6      6      1      0            ./home
61405.848231   e89fcd33936c     4026532402   4026532405   0      lstat            ls               6      6      1      0            ./lib
61405.848290   e89fcd33936c     4026532402   4026532405   0      lstat            ls               6      6      1      0            ./root
61405.848348   e89fcd33936c     4026532402   4026532405   0      lstat            ls               6      6      1      0            ./bin
61405.848408   e89fcd33936c     4026532402   4026532405   0      lstat            ls               6      6      1      0            ./etc
61405.848476   e89fcd33936c     4026532402   4026532405   0      cap_capable      ls               6      6      1      0            CAP_SYS_ADMIN
61405.848523   e89fcd33936c     4026532402   4026532405   0      lstat            ls               6      6      1      0            ./run
61405.848599   e89fcd33936c     4026532402   4026532405   0      cap_capable      ls               6      6      1      0            CAP_SYS_ADMIN
61405.848643   e89fcd33936c     4026532402   4026532405   0      lstat            ls               6      6      1      0            ./srv
61405.848707   e89fcd33936c     4026532402   4026532405   0      lstat            ls               6      6      1      0            ./proc
61405.848774   e89fcd33936c     4026532402   4026532405   0      cap_capable      ls               6      6      1      0            CAP_SYS_ADMIN
61405.848817   e89fcd33936c     4026532402   4026532405   0      lstat            ls               6      6      1      0            ./opt
61405.848879   e89fcd33936c     4026532402   4026532405   0      lstat            ls               6      6      1      0            ./dev
61405.848946   e89fcd33936c     4026532402   4026532405   0      cap_capable      ls               6      6      1      0            CAP_SYS_ADMIN
61405.848989   e89fcd33936c     4026532402   4026532405   0      lstat            ls               6      6      1      0            ./var
61405.849061   e89fcd33936c     4026532402   4026532405   0      cap_capable      ls               6      6      1      0            CAP_SYS_ADMIN
61405.849097   e89fcd33936c     4026532402   4026532405   0      lstat            ls               6      6      1      0            ./mnt
61405.849123   e89fcd33936c     4026532402   4026532405   0      cap_capable      ls               6      6      1      0            CAP_SYS_ADMIN
61405.849139   e89fcd33936c     4026532402   4026532405   0      lstat            ls               6      6      1      0            ./tmp
61405.849163   e89fcd33936c     4026532402   4026532405   0      cap_capable      ls               6      6      1      0            CAP_SYS_ADMIN
61405.849178   e89fcd33936c     4026532402   4026532405   0      lstat            ls               6      6      1      0            ./media
61405.849201   e89fcd33936c     4026532402   4026532405   0      getdents64       ls               6      6      1      0            3
61405.849220   e89fcd33936c     4026532402   4026532405   0      close            ls               6      6      1      0            3
61405.849280   e89fcd33936c     4026532402   4026532405   0      ioctl            ls               6      6      1      0            1 21523
61405.849318   e89fcd33936c     4026532402   4026532405   0      do_exit          ls               6      6      1      0
```

As can be seen in the above output, each event line shows the following information about the event:

* TIME - shows the event time relative to system boot time in seconds
* UTS_NAME - uts namespace name. As there is no container id object in the kernel, and docker/k8s will usually set this to the container id, we use this field to distinguish between containers.
* MNT_NS - mount namespace inode number.
* PID_NS - pid namespace inode number. In order to know if there are different containers in the same pid namespace (e.g. in a k8s pod), it is possible to check this value
* UID - real user id (in host user namespace) of the calling process
* EVENT - identifies the event (e.g. syscall name)
* COMM - name of the calling process
* PID - pid of the calling process
* TID - tid of the calling thread
* PPID - parent pid of the calling process
* RET - value returned by the function
* ARGS - list of arguments given

Note about string arguments and userspace pointers: as pointers are being dereferenced from userspace memory, a malicious program may change the content being read before it actually gets executed in the kernel. Take this into account when doing security related stuff.

Tracee currently supports a subset of system calls events, which can be listed with:

`./start.py -l`

Other supported events are (functions called in kernel space):

* cap_capable - indicates which capabilities were requested
* do_exit - indicates exited processes


Adding new events (especially system calls) to Tracee is straightforward, but one should keep in mind that tracing too many events may cause system performance degradation. Other than that, as perf event buffer is limited in size (2^17), having too many events can cause samples to be lost (an error message will then be shown as part of the output). For this reason, *read* and *write* syscalls are deliberately excluded from Tracee.


## TODO

* Add envp to execve(at) syscalls. Put argv and envp in a list instead being different param for each arg
* Add full sockaddr struct fields to: "connect", "accept", "bind", "getsockname"
* Consider tracing commit_creds to detect potential kernel exploits
* Add check for head and tail to avoid overflow in the submission buffer
* Change submission_buf size from 32 to num_of_cpu which can be determined by userspace and set accordingly
* Consider re-writing userspace side (python) in golang
* Reduce number of missing events by optimizing event_t to use 4 bytes (sent by perf_submit)

## Known Issues

* Pathname is missing in execve(at) syscalls - Issue #2627 in BCC project
* Lost events when event rate is high

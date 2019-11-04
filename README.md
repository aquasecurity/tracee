# Tracee
Container tracing using eBPF

**Tracee** is a lightweight, easy to use container tracing tool.
After launching the tool, it will start collecting traces of newly created containers.
The collected traces are mostly system calls performed by the processes running inside the containers,
but other events, such as capabilities required to perform the actions requested by the container, are also supported.

## Requirements
Currently requires 
* kernel version 4.14-4.18
* BCC

## Quick Start Instructions

As root: `./start.py -v`

Following is an output example of Tracee after running
`docker run -it --rm alpine sh`

```
TIME(s)        MNT_NS       PID_NS       UID    EVENT            COMM             PID    TID    PPID   RET              ARGS
1831.335358    4026532726   4026532729   0      execve           runc:[2:INIT]    1      1      4982   0                /bin/sh
1831.342042    4026532726   4026532729   0      cap_capable      runc:[2:INIT]    1      1      4982   0                CAP_SYS_ADMIN
1831.345894    4026532726   4026532729   0      do_exit          runc:[2:INIT]    1      3      4982   0                
1831.345867    4026532726   4026532729   0      do_exit          runc:[2:INIT]    1      2      4982   0                
1831.345891    4026532726   4026532729   0      do_exit          runc:[2:INIT]    1      4      4982   0                
1831.345894    4026532726   4026532729   0      do_exit          runc:[2:INIT]    1      5      4982   0                
1831.397760    4026532726   4026532729   0      mprotect         sh               1      1      4982   0                0x7faed75ae000 4096 1
1831.424309    4026532726   4026532729   0      mprotect         sh               1      1      4982   0                0x5614f9c38000 16384 1
1831.464215    4026532726   4026532729   0      ioctl            sh               1      1      4982   0                0 21523
1831.464289    4026532726   4026532729   0      ioctl            sh               1      1      4982   0                1 21523
1831.464434    4026532726   4026532729   0      open             sh               1      1      4982   3                /dev/tty O_RDWR
1831.464516    4026532726   4026532729   0      close            sh               1      1      4982   0                3
1831.464578    4026532726   4026532729   0      ioctl            sh               1      1      4982   0                10 21519
1831.464682    4026532726   4026532729   0      ioctl            sh               1      1      4982   0                10 21520
1831.464874    4026532726   4026532729   0      stat             sh               1      1      4982   -2               MAILPATH
1831.464983    4026532726   4026532729   0      ioctl            sh               1      1      4982   0                0 21505
1831.465119    4026532726   4026532729   0      cap_capable      sh               1      1      4982   0                CAP_SYS_ADMIN
1831.465985    4026532726   4026532729   0      open             sh               1      1      4982   -2               /root/.ash_history O_RDONLY
1831.466178    4026532726   4026532729   0      ioctl            sh               1      1      4982   0                0 21506
1831.466621    4026532726   4026532729   0      open             sh               1      1      4982   3                /etc/passwd O_RDONLY|O_CLOEXEC
1831.466808    4026532726   4026532729   0      close            sh               1      1      4982   0                3
1831.466897    4026532726   4026532729   0      ioctl            sh               1      1      4982   0                0 21523
1831.467013    4026532726   4026532729   0      ioctl            sh               1      1      4982   0                1 21523
```

Executing `ls` in the alpine container shell will trigger the following events:

```
6663.261031    4026532726   4026532729   0      cap_capable      sh               1      1      4982   0                CAP_SYS_ADMIN
6663.261136    4026532726   4026532729   0      cap_capable      sh               1      1      4982   0                CAP_DAC_READ_SEARCH
6663.261197    4026532726   4026532729   0      cap_capable      sh               1      1      4982   0                CAP_DAC_OVERRIDE
6663.261417    4026532726   4026532729   0      cap_capable      sh               1      1      4982   0                CAP_SYS_ADMIN
6663.261476    4026532726   4026532729   0      cap_capable      sh               1      1      4982   0                CAP_DAC_OVERRIDE
6663.261639    4026532726   4026532729   0      open             sh               1      1      4982   3                /root/.ash_history O_WRONLY|O_CREAT|O_APPEND
6663.261767    4026532726   4026532729   0      close            sh               1      1      4982   0                3
6663.261842    4026532726   4026532729   0      ioctl            sh               1      1      4982   0                0 21506
6663.261952    4026532726   4026532729   0      stat             sh               1      1      4982   -2               /usr/local/sbin/ls
6663.262038    4026532726   4026532729   0      stat             sh               1      1      4982   -2               /usr/local/bin/ls
6663.262111    4026532726   4026532729   0      stat             sh               1      1      4982   -2               /usr/sbin/ls
6663.262182    4026532726   4026532729   0      stat             sh               1      1      4982   -2               /usr/bin/ls
6663.262251    4026532726   4026532729   0      stat             sh               1      1      4982   -2               /sbin/ls
6663.262352    4026532726   4026532729   0      stat             sh               1      1      4982   0                /bin/ls
6663.262841    4026532726   4026532729   0      fork             sh               1      1      4982   6                
6663.263061    4026532726   4026532729   0      ioctl            sh               6      6      1      0                10 21520
6663.263186    4026532726   4026532729   0      execve           sh               6      6      1      0                /bin/ls
6663.264062    4026532726   4026532729   0      mprotect         ls               6      6      1      0                0x7fbf4fda0000 4096 1
6663.264359    4026532726   4026532729   0      mprotect         ls               6      6      1      0                0x55c241339000 16384 1
6663.277057    4026532726   4026532729   0      ioctl            ls               6      6      1      0                0 21523
6663.277102    4026532726   4026532729   0      ioctl            ls               6      6      1      0                1 21523
6663.277124    4026532726   4026532729   0      ioctl            ls               6      6      1      0                1 21523
6663.277171    4026532726   4026532729   0      stat             ls               6      6      1      0                .
6663.277206    4026532726   4026532729   0      open             ls               6      6      1      3                . O_RDONLY|O_DIRECTORY|O_CLOEXEC
6663.277310    4026532726   4026532729   0      getdents64       ls               6      6      1      496              3
6663.277349    4026532726   4026532729   0      lstat            ls               6      6      1      0                ./sys
6663.277371    4026532726   4026532729   0      lstat            ls               6      6      1      0                ./usr
6663.277392    4026532726   4026532729   0      lstat            ls               6      6      1      0                ./sbin
6663.277457    4026532726   4026532729   0      cap_capable      ls               6      6      1      0                CAP_SYS_ADMIN
6663.277480    4026532726   4026532729   0      lstat            ls               6      6      1      0                ./home
6663.277507    4026532726   4026532729   0      lstat            ls               6      6      1      0                ./lib
6663.277532    4026532726   4026532729   0      lstat            ls               6      6      1      0                ./root
6663.277559    4026532726   4026532729   0      lstat            ls               6      6      1      0                ./bin
6663.277589    4026532726   4026532729   0      lstat            ls               6      6      1      0                ./etc
6663.277624    4026532726   4026532729   0      cap_capable      ls               6      6      1      0                CAP_SYS_ADMIN
6663.277642    4026532726   4026532729   0      lstat            ls               6      6      1      0                ./run
6663.277676    4026532726   4026532729   0      cap_capable      ls               6      6      1      0                CAP_SYS_ADMIN
6663.277697    4026532726   4026532729   0      lstat            ls               6      6      1      0                ./srv
6663.277731    4026532726   4026532729   0      lstat            ls               6      6      1      0                ./proc
6663.277776    4026532726   4026532729   0      cap_capable      ls               6      6      1      0                CAP_SYS_ADMIN
6663.277803    4026532726   4026532729   0      lstat            ls               6      6      1      0                ./opt
6663.277841    4026532726   4026532729   0      lstat            ls               6      6      1      0                ./dev
6663.283841    4026532726   4026532729   0      ioctl            sh               1      1      4982   0                10 21520
6663.283903    4026532726   4026532729   0      stat             sh               1      1      4982   -2               MAILPATH
6663.283970    4026532726   4026532729   0      ioctl            sh               1      1      4982   0                0 21505
6663.284003    4026532726   4026532729   0      ioctl            sh               1      1      4982   0                0 21506
6663.284045    4026532726   4026532729   0      open             sh               1      1      4982   3                /etc/passwd O_RDONLY|O_CLOEXEC
6663.284091    4026532726   4026532729   0      close            sh               1      1      4982   0                3
6663.284119    4026532726   4026532729   0      ioctl            sh               1      1      4982   0                0 21523
6663.283112    4026532726   4026532729   0      cap_capable      ls               6      6      1      0                CAP_SYS_ADMIN
6663.283166    4026532726   4026532729   0      lstat            ls               6      6      1      0                ./var
6663.283243    4026532726   4026532729   0      cap_capable      ls               6      6      1      0                CAP_SYS_ADMIN
6663.283263    4026532726   4026532729   0      lstat            ls               6      6      1      0                ./mnt
6663.283303    4026532726   4026532729   0      cap_capable      ls               6      6      1      0                CAP_SYS_ADMIN
6663.283322    4026532726   4026532729   0      lstat            ls               6      6      1      0                ./tmp
6663.283354    4026532726   4026532729   0      cap_capable      ls               6      6      1      0                CAP_SYS_ADMIN
6663.283371    4026532726   4026532729   0      lstat            ls               6      6      1      0                ./media
6663.283403    4026532726   4026532729   0      getdents64       ls               6      6      1      0                3
6663.283434    4026532726   4026532729   0      close            ls               6      6      1      0                3
6663.283534    4026532726   4026532729   0      ioctl            ls               6      6      1      0                1 21523
6663.283587    4026532726   4026532729   0      do_exit          ls               6      6      1      0                
```

As can be seen in the above output, each event line shows the following information about the event:

* TIME - shows the event time relative to system boot time in seconds
* MNT_NS - mount namespace inode number. As there is no container id object in the kernel, and every container is in a different mount namespace, we use this field to distinguish between containers
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

Tracee currently supports the following system calls:

* execve
* execveat
* mmap
* mprotect
* clone
* fork
* vfork
* newstat
* newfstat
* newlstat
* mknod
* mknodat
* dup
* dup2
* dup3
* memfd_create
* socket
* close
* ioctl
* access
* faccessat
* kill
* listen
* connect
* accept
* accept4
* bind
* getsockname
* prctl
* ptrace
* process_vm_writev
* process_vm_readv
* init_module
* finit_module
* delete_module
* symlink
* symlinkat
* getdents
* getdents64
* creat
* open
* openat

Other supported events are (functions called in kernel space):

* cap_capable - indicates which capabilities were requested
* do_exit - indicates exited processes


Adding new events (especially system calls) to Tracee is straightforward, but one should keep in mind that tracing too many events may cause system performance degradation. Other than that, as perf event buffer is limited in size (2^17), having too many events can cause samples to be lost (an error message will then be shown as part of the output). For this reason, *read* and *write* syscalls are deliberately excluded from Tracee.


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
* Lost events when event rate is high

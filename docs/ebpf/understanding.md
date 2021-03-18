Here's a sample output of running Tracee-eBPF with no additional arguments:

```
TIME(s)        UID    COMM             PID     TID     RET             EVENT                ARGS
176751.746515  1000   zsh              14726   14726   0               execve               pathname: /usr/bin/ls, argv: [ls]
176751.746772  1000   zsh              14726   14726   0               security_bprm_check  pathname: /usr/bin/ls, dev: 8388610, inode: 777
176751.747044  1000   ls               14726   14726  -2               access               pathname: /etc/ld.so.preload, mode: R_OK
176751.747077  1000   ls               14726   14726   0               security_file_open   pathname: /etc/ld.so.cache, flags: O_RDONLY|O_LARGEFILE, dev: 8388610, inode: 533737
...
```

Each line is a single event collected by Tracee-eBPF, with the following information:

1. TIME - shows the event time relative to system boot time in seconds
2. UID - real user id (in host user namespace) of the calling process
3. COMM - name of the calling process
4. PID - pid of the calling process
5. TID - tid of the calling thread
6. RET - value returned by the function
7. EVENT - identifies the event (e.g. syscall name)
8. ARGS - list of arguments given to the function

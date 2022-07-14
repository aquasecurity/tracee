# Tracing Output Options

In order to check latest output options you may execute:

```text
$ sudo ./dist/tracee-ebpf --output help
$ sudo ./dist/tracee-ebpf --output option:xxx
```

Tracee supports different output options for detected events:

1. **option:stack-addresses**  

    Pick stack memory address from each event

    ```text
    $ sudo ./dist/tracee-ebpf --output json --trace comm=bash --trace follow --trace event=openat --output option:stack-addresses
    ```

    ```json
    {"timestamp":1657291777566819000,"threadStartTime":616858353946737,"processorId":9,"processId":1948212,"cgroupId":1,"threadId":1948212,"parentProcessId":3795408,"hostProcessId":1948212,"hostThreadId":1948212,"hostParentProcessId":3795408,"userId":1000,"mountNamespace":4026531840,"pidNamespace":4026531836,"processName":"exa","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"257","eventName":"openat","argsNum":4,"returnValue":3,"stackAddresses":[140395297729336,140395297614210],"args":[{"name":"dirfd","type":"int","value":-100},{"name":"pathname","type":"const char*","value":"/etc/ld.so.cache"},{"name":"flags","type":"int","value":524288},{"name":"mode","type":"mode_t","value":0}]}
    ```

2. **option:detect-syscall**

    If you are filtering for an event that is not a syscall
    ("security_file_open", for example), which sometimes is needed to avoid
    [TOCTOU](https://blog.aquasec.com/linux-vulnerabilitie-tracee), you may
    opt to also detect which syscal has generated that event.

    ```text
    $ sudo ./dist/tracee-ebpf --output json --trace comm=bash --trace follow --trace event=security_file_open --output option:detect-syscall
    ```

    ```json
    {"timestamp":1657291989963764000,"threadStartTime":617070752926681,"processorId":11,"processId":1986397,"cgroupId":1,"threadId":1986397,"parentProcessId":3795408,"hostProcessId":1986397,"hostThreadId":1986397,"hostParentProcessId":3795408,"userId":1000,"mountNamespace":4026531840,"pidNamespace":4026531836,"processName":"bash","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"722","eventName":"security_file_open","argsNum":7,"returnValue":0,"stackAddresses":null,"args":[{"name":"pathname","type":"const char*","value":"/usr/bin/exa"},{"name":"flags","type":"int","value":32800},{"name":"dev","type":"dev_t","value":271581185},{"name":"inode","type":"unsigned long","value":2493759},{"name":"ctime","type":"unsigned long","value":1653730234432691500},{"name":"syscall_pathname","type":"const char*","value":""},{"name":"syscall","type":"int","value":59}]}
    {"timestamp":1657291989963871500,"threadStartTime":617070752926681,"processorId":11,"processId":1986397,"cgroupId":1,"threadId":1986397,"parentProcessId":3795408,"hostProcessId":1986397,"hostThreadId":1986397,"hostParentProcessId":3795408,"userId":1000,"mountNamespace":4026531840,"pidNamespace":4026531836,"processName":"bash","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"722","eventName":"security_file_open","argsNum":7,"returnValue":0,"stackAddresses":null,"args":[{"name":"pathname","type":"const char*","value":"/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"},{"name":"flags","type":"int","value":32800},{"name":"dev","type":"dev_t","value":271581185},{"name":"inode","type":"unsigned long","value":2752590},{"name":"ctime","type":"unsigned long","value":1653730015033811700},{"name":"syscall_pathname","type":"const char*","value":""},{"name":"syscall","type":"int","value":59}]}
    ```

    Observe that the event now has the following extra argument:

    ```json
    {"name":"syscall","type":"int","value":59}
    ```

    Which means the event that has generated that event was `sys_execve`
    (syscall 59 in amd64 architecture).

    !!! tip
        If you pay attention to previous outputs, we have raw event data in
        many places. Like the syscall example above, where we have to find out
        which syscall it was referring to. Check **parse-arguments** option
        below to improve your experience.

3. **option:parse-arguments**

    In order to have a better experience with the output provided by
    **tracee-ebpf**, you may opt to parse event arguments to a **human
    *readable** format.

    ```text
    $ sudo ./dist/tracee-ebpf --output json --trace comm=bash --trace follow --trace event=security_file_open --output option:detect-syscall --output option:parse-arguments
    ```
    ```json
    {"timestamp":1657292314817581101,"threadStartTime":617395606682013,"processorId":9,"processId":2045288,"cgroupId":1,"threadId":2045288,"parentProcessId":3795408,"hostProcessId":2045288,"hostThreadId":2045288,"hostParentProcessId":3795408,"userId":1000,"mountNamespace":4026531840,"pidNamespace":4026531836,"processName":"bash","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"722","eventName":"security_file_open","argsNum":7,"returnValue":0,"stackAddresses":null,"args":[{"name":"pathname","type":"const char*","value":"/usr/bin/exa"},{"name":"flags","type":"string","value":"O_RDONLY|O_LARGEFILE"},{"name":"dev","type":"dev_t","value":271581185},{"name":"inode","type":"unsigned long","value":2493759},{"name":"ctime","type":"unsigned long","value":1653730234432691496},{"name":"syscall_pathname","type":"const char*","value":""},{"name":"syscall","type":"int","value":"execve"}]}
    {"timestamp":1657292314817690279,"threadStartTime":617395606682013,"processorId":9,"processId":2045288,"cgroupId":1,"threadId":2045288,"parentProcessId":3795408,"hostProcessId":2045288,"hostThreadId":2045288,"hostParentProcessId":3795408,"userId":1000,"mountNamespace":4026531840,"pidNamespace":4026531836,"processName":"bash","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"722","eventName":"security_file_open","argsNum":7,"returnValue":0,"stackAddresses":null,"args":[{"name":"pathname","type":"const char*","value":"/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"},{"name":"flags","type":"string","value":"O_RDONLY|O_LARGEFILE"},{"name":"dev","type":"dev_t","value":271581185},{"name":"inode","type":"unsigned long","value":2752590},{"name":"ctime","type":"unsigned long","value":1653730015033811838},{"name":"syscall_pathname","type":"const char*","value":""},{"name":"syscall","type":"int","value":"execve"}]}
    ```

    As you can see now, the syscall that generated the event
    **security_file_open** was indeed **execve**:

    ```json
    {"name":"syscall","type":"int","value":"execve"}
    ```

4. **option:exec-env**

    Sometimes it is also important to know the execution environment variables
    whenever an event is detected, specially when deteting **execve** event.

    ```text
    $ sudo ./dist/tracee-ebpf --output json --trace comm=bash --trace follow --trace event=execve --output option:parse-arguments --output option:exec-env
    ```

    ```json
    {"timestamp":1657294974430672155,"threadStartTime":620055219867435,"processorId":11,"processId":2531912,"cgroupId":1,"threadId":2531912,"parentProcessId":2490011,"hostProcessId":2531912,"hostThreadId":2531912,"hostParentProcessId":2490011,"userId":1000,"mountNamespace":4026531840,"pidNamespace":4026531836,"processName":"bash","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"59","eventName":"execve","argsNum":3,"returnValue":0,"stackAddresses":null,"args":[{"name":"pathname","type":"const char*","value":"/bin/ls"},{"name":"argv","type":"const char*const*","value":["ls"]},{"name":"envp","type":"const char*const*","value":["SHELL=/bin/bash","COLORTERM=truecolor","LESS=-RF --mouse","HISTCONTROL=ignoreboth","HISTSIZE=1000000","DEBFULLNAME=Rafael David Tinoco","EDITOR=nvim","PWD=/home/rafaeldtinoco/work/ebpf/tracee","LOGNAME=rafaeldtinoco","DEB_BUILD_PROFILES=parallel=36 nocheck nostrip noudeb doc","LINES=82","HOME=/home/rafaeldtinoco","LANG=C.UTF-8","COLUMNS=106","MANROFFOPT=-c","DEBEMAIL=rafaeldtinoco@ubuntu.com","LC_TERMINAL=iTerm2","PROMPT_COMMAND=echo -ne \"\\033]0;$what\\007\"; history -a","BAT_THEME=GitHub","TERM=screen-256color","USER=rafaeldtinoco","GIT_PAGER=batcat --theme=\"GitHub\" -p --pager=less --tabs 0","MANPAGER=bash -c 'col -bx | batcat --theme=\"GitHub\" -l man -p'","LC_TERMINAL_VERSION=3.5.0beta5","DEB_BUILD_OPTIONS=parallel=36 nocheck nostrip noudeb doc","SHLVL=2","PAGER=batcat --theme=\"GitHub\" -p --pager=less --tabs 0","BAT_STYLE=plain","PROMPT_DIRTRIM=2","SYSTEMD_PAGER=batcat --theme=\"GitHub\" -p --pager=less --tabs 0","LC_CTYPE=C.UTF-8","LESS_HISTFILE=/dev/null","PS1=\\u@\\h \\w $ ","PATH=/home/rafaeldtinoco/bin:/home/rafaeldtinoco/go/bin:.:/sbin:/bin:/usr/sbin:/usr/bin:/snap/bin:/snap/sbin:/usr/local/bin:/usr/local/sbin:/usr/games/","HISTFILESIZE=1000000","DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus","SSH_TTY=/dev/pts/3","OLDPWD=/home/rafaeldtinoco","_=/bin/ls"]}]}
    ```

    As  you can see, from the execve event we can also see the process
    environment variables in place:

    ```json
    {"name":"envp","type":"const char*const*","value":["SHELL=/bin/bash","COLORTERM=truecolor","LESS=-RF --mouse","HISTCONTROL=ignoreboth","HISTSIZE=1000000","DEBFULLNAME=Rafael David Tinoco","EDITOR=nvim","PWD=/home/rafaeldtinoco/work/ebpf/tracee","LOGNAME=rafaeldtinoco","DEB_BUILD_PROFILES=parallel=36 nocheck nostrip noudeb doc","LINES=82","HOME=/home/rafaeldtinoco","LANG=C.UTF-8","COLUMNS=106","MANROFFOPT=-c","DEBEMAIL=rafaeldtinoco@ubuntu.com","LC_TERMINAL=iTerm2","PROMPT_COMMAND=echo -ne \"\\033]0;$what\\007\"; history -a","BAT_THEME=GitHub","TERM=screen-256color","USER=rafaeldtinoco","GIT_PAGER=batcat --theme=\"GitHub\" -p --pager=less --tabs 0","MANPAGER=bash -c 'col -bx | batcat --theme=\"GitHub\" -l man -p'","LC_TERMINAL_VERSION=3.5.0beta5","DEB_BUILD_OPTIONS=parallel=36 nocheck nostrip noudeb doc","SHLVL=2","PAGER=batcat --theme=\"GitHub\" -p --pager=less --tabs 0","BAT_STYLE=plain","PROMPT_DIRTRIM=2","SYSTEMD_PAGER=batcat --theme=\"GitHub\" -p --pager=less --tabs 0","LC_CTYPE=C.UTF-8","LESS_HISTFILE=/dev/null","PS1=\\u@\\h \\w $ ","PATH=/home/rafaeldtinoco/bin:/home/rafaeldtinoco/go/bin:.:/sbin:/bin:/usr/sbin:/usr/bin:/snap/bin:/snap/sbin:/usr/local/bin:/usr/local/sbin:/usr/games/","HISTFILESIZE=1000000","DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus","SSH_TTY=/dev/pts/3","OLDPWD=/home/rafaeldtinoco","_=/bin/ls"]}
    ```

5. **option:exec-hash**

    This is a special output option for **sched_process_exec** so user can get
    the **file hash** and **process ctime** (particularly interesting if you
    would like to compare executed binaries from a list of known hashes, for
    example).

    ```text
    $ sudo ./dist/tracee-ebpf --output json --trace comm=bash --trace follow --trace event=sched_process_exec --output option:parse-arguments --output option:exec-hash
    ```

    ```json
    {"timestamp":1657295236470126167,"threadStartTime":620317257297855,"processorId":3,"processId":2578324,"cgroupId":1,"threadId":2578324,"parentProcessId":2578238,"hostProcessId":2578324,"hostThreadId":2578324,"hostParentProcessId":2578238,"userId":1000,"mountNamespace":4026531840,"pidNamespace":4026531836,"processName":"exa","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"707","eventName":"sched_process_exec","argsNum":14,"returnValue":0,"stackAddresses":null,"args":[{"name":"cmdpath","type":"const char*","value":"/bin/exa"},{"name":"pathname","type":"const char*","value":"/usr/bin/exa"},{"name":"argv","type":"const char**","value":["exa","--color=auto"]},{"name":"dev","type":"dev_t","value":271581185},{"name":"inode","type":"unsigned long","value":2493759},{"name":"invoked_from_kernel","type":"int","value":0},{"name":"ctime","type":"unsigned long","value":1653730234432691496},{"name":"stdin_type","type":"string","value":"S_IFCHR"},{"name":"inode_mode","type":"umode_t","value":33261},{"name":"interp","type":"const char*","value":"/bin/exa"},{"name":"interpreter_pathname","type":"const char*","value":"/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"},{"name":"interpreter_dev","type":"dev_t","value":271581185},{"name":"ineterpreter_inode","type":"unsigned long","value":2752590},{"name":"sha256","type":"const char*","value":""}]}
    ```

    At the end of the event, you will also get information about the loader 

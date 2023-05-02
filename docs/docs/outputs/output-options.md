# Tracing Output Options

Tracee supports different output options for customizing the way events are printed. For a complete list of available options, run `tracee --help output`.

Available options:

1. **option:stack-addresses**  

    Pick stack memory address from each event

    ```console
    sudo ./dist/tracee --output json --filter comm=bash --filter follow --filter event=openat --output option:stack-addresses
    ```

    ```json
    {"timestamp":1657291777566819000,"threadStartTime":616858353946737,"processorId":9,"processId":1948212,"cgroupId":1,"threadId":1948212,"parentProcessId":3795408,"hostProcessId":1948212,"hostThreadId":1948212,"hostParentProcessId":3795408,"userId":1000,"mountNamespace":4026531840,"pidNamespace":4026531836,"processName":"exa","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"257","eventName":"openat","argsNum":4,"returnValue":3,"stackAddresses":[140395297729336,140395297614210],"args":[{"name":"dirfd","type":"int","value":-100},{"name":"pathname","type":"const char*","value":"/etc/ld.so.cache"},{"name":"flags","type":"int","value":524288},{"name":"mode","type":"mode_t","value":0}]}
    ```

2. **option:parse-arguments**

    In order to have a better experience with the output provided by
    **tracee**, you may opt to parse event arguments to a **human
    *readable** format.

    ```console
    sudo ./dist/tracee --output json --filter comm=bash --filter follow --filter event=security_file_open --output option:parse-arguments
    ```

    ```json
    {"timestamp":1657292314817581101,"threadStartTime":617395606682013,"processorId":9,"processId":2045288,"cgroupId":1,"threadId":2045288,"parentProcessId":3795408,"hostProcessId":2045288,"hostThreadId":2045288,"hostParentProcessId":3795408,"userId":1000,"mountNamespace":4026531840,"pidNamespace":4026531836,"processName":"bash","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"722","eventName":"security_file_open","argsNum":7,"returnValue":0,"stackAddresses":null,"syscall":"execve","contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"pathname","type":"const char*","value":"/usr/bin/exa"},{"name":"flags","type":"string","value":"O_RDONLY|O_LARGEFILE"},{"name":"dev","type":"dev_t","value":271581185},{"name":"inode","type":"unsigned long","value":2493759},{"name":"ctime","type":"unsigned long","value":1653730234432691496},{"name":"syscall_pathname","type":"const char*","value":""}]}
    {"timestamp":1657292314817690279,"threadStartTime":617395606682013,"processorId":9,"processId":2045288,"cgroupId":1,"threadId":2045288,"parentProcessId":3795408,"hostProcessId":2045288,"hostThreadId":2045288,"hostParentProcessId":3795408,"userId":1000,"mountNamespace":4026531840,"pidNamespace":4026531836,"processName":"bash","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"722","eventName":"security_file_open","argsNum":7,"returnValue":0,"stackAddresses":null,"syscall":"execve","contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"pathname","type":"const char*","value":"/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"},{"name":"flags","type":"string","value":"O_RDONLY|O_LARGEFILE"},{"name":"dev","type":"dev_t","value":271581185},{"name":"inode","type":"unsigned long","value":2752590},{"name":"ctime","type":"unsigned long","value":1653730015033811838},{"name":"syscall_pathname","type":"const char*","value":""}]}
    ```

    As you can see now, the files were opened with the **O_RDONLY** and **O_LARGEFILE**
    flags. The names of the flags are received instead of the real raw int value:

    ```json
    {"name":"flags","type":"string","value":"O_RDONLY|O_LARGEFILE"}
    ```

3. **option:parse-arguments-fds**

    In order to have a better experience with the output provided by
    **tracee**, you may opt to parse event fd arguments to be
    enriched with **file paths**. This option also enables `parse-arguments`.

    ```console
    sudo ./dist/tracee --output json --filter comm=bash --filter follow --filter event=read --output option:parse-arguments-fds
    ```

    ```json
    {"timestamp":1658356809979365547,"threadStartTime":11570447751601,"processorId":1,"processId":239413,"cgroupId":10575,"threadId":239413,"parentProcessId":91515,"hostProcessId":239413,"hostThreadId":239413,"hostParentProcessId":91515,"userId":1000,"mountNamespace":4026531840,"pidNamespace":4026531836,"processName":"cat","hostName":"ubuntu-impish","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"0","eventName":"read","argsNum":3,"returnValue":0,"stackAddresses":null,"syscall":"read","contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"fd","type":"int","value":"3=/etc/locale.alias"},{"name":"buf","type":"void*","value":93921853269152},{"name":"count","type":"size_t","value":4096}]}
    {"timestamp":1658356809979748006,"threadStartTime":11570447751601,"processorId":1,"processId":239413,"cgroupId":10575,"threadId":239413,"parentProcessId":91515,"hostProcessId":239413,"hostThreadId":239413,"hostParentProcessId":91515,"userId":1000,"mountNamespace":4026531840,"pidNamespace":4026531836,"processName":"cat","hostName":"ubuntu-impish","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"0","eventName":"read","argsNum":3,"returnValue":1867,"stackAddresses":null,"syscall":"read","contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"fd","type":"int","value":"3=/etc/passwd"},{"name":"buf","type":"void*","value":139658814046208},{"name":"count","type":"size_t","value":131072}]}
    ```

    As you can see now, the value of fd is enriched with its file path following the `"fd=filepath"` format (string type in JSON).

    ```json
    {"name":"fd","type":"int","value":"3=/etc/locale.alias"}
    ...
    {"name":"fd","type":"int","value":"3=/etc/passwd"}
    ```


4. **option:exec-env**

    Sometimes it is also important to know the execution environment variables
    whenever an event is detected, specially when detecting **execve** event.

    ```console
    sudo ./dist/tracee --output json --filter comm=bash --filter follow --filter event=execve --output option:parse-arguments --output option:exec-env
    ```

    ```json
    {"timestamp":1657294974430672155,"threadStartTime":620055219867435,"processorId":11,"processId":2531912,"cgroupId":1,"threadId":2531912,"parentProcessId":2490011,"hostProcessId":2531912,"hostThreadId":2531912,"hostParentProcessId":2490011,"userId":1000,"mountNamespace":4026531840,"pidNamespace":4026531836,"processName":"bash","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"59","eventName":"execve","argsNum":3,"returnValue":0,"stackAddresses":null,"syscall":"execve","contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"pathname","type":"const char*","value":"/bin/ls"},{"name":"argv","type":"const char*const*","value":["ls"]},{"name":"envp","type":"const char*const*","value":["SHELL=/bin/bash","COLORTERM=truecolor","LESS=-RF --mouse","HISTCONTROL=ignoreboth","HISTSIZE=1000000","DEBFULLNAME=Rafael David Tinoco","EDITOR=nvim","PWD=/home/rafaeldtinoco/work/ebpf/tracee","LOGNAME=rafaeldtinoco","DEB_BUILD_PROFILES=parallel=36 nocheck nostrip noudeb doc","LINES=82","HOME=/home/rafaeldtinoco","LANG=C.UTF-8","COLUMNS=106","MANROFFOPT=-c","DEBEMAIL=rafaeldtinoco@ubuntu.com","LC_TERMINAL=iTerm2","PROMPT_COMMAND=echo -ne \"\\033]0;$what\\007\"; history -a","BAT_THEME=GitHub","TERM=screen-256color","USER=rafaeldtinoco","GIT_PAGER=batcat --theme=\"GitHub\" -p --pager=less --tabs 0","MANPAGER=bash -c 'col -bx | batcat --theme=\"GitHub\" -l man -p'","LC_TERMINAL_VERSION=3.5.0beta5","DEB_BUILD_OPTIONS=parallel=36 nocheck nostrip noudeb doc","SHLVL=2","PAGER=batcat --theme=\"GitHub\" -p --pager=less --tabs 0","BAT_STYLE=plain","PROMPT_DIRTRIM=2","SYSTEMD_PAGER=batcat --theme=\"GitHub\" -p --pager=less --tabs 0","LC_CTYPE=C.UTF-8","LESS_HISTFILE=/dev/null","PS1=\\u@\\h \\w $ ","PATH=/home/rafaeldtinoco/bin:/home/rafaeldtinoco/go/bin:.:/sbin:/bin:/usr/sbin:/usr/bin:/snap/bin:/snap/sbin:/usr/local/bin:/usr/local/sbin:/usr/games/","HISTFILESIZE=1000000","DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus","SSH_TTY=/dev/pts/3","OLDPWD=/home/rafaeldtinoco","_=/bin/ls"]}]}
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

    ```console
    sudo ./dist/tracee --output json --filter comm=bash --filter follow --filter event=sched_process_exec --output option:parse-arguments --output option:exec-hash
    ```

    ```json
    {"timestamp":1657295236470126167,"threadStartTime":620317257297855,"processorId":3,"processId":2578324,"cgroupId":1,"threadId":2578324,"parentProcessId":2578238,"hostProcessId":2578324,"hostThreadId":2578324,"hostParentProcessId":2578238,"userId":1000,"mountNamespace":4026531840,"pidNamespace":4026531836,"processName":"exa","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"707","eventName":"sched_process_exec","argsNum":14,"returnValue":0,"stackAddresses":null,"syscall":"execve","contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"cmdpath","type":"const char*","value":"/bin/exa"},{"name":"pathname","type":"const char*","value":"/usr/bin/exa"},{"name":"argv","type":"const char**","value":["exa","--color=auto"]},{"name":"dev","type":"dev_t","value":271581185},{"name":"inode","type":"unsigned long","value":2493759},{"name":"invoked_from_kernel","type":"int","value":0},{"name":"ctime","type":"unsigned long","value":1653730234432691496},{"name":"stdin_type","type":"string","value":"S_IFCHR"},{"name":"inode_mode","type":"umode_t","value":33261},{"name":"interp","type":"const char*","value":"/bin/exa"},{"name":"interpreter_pathname","type":"const char*","value":"/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"},{"name":"interpreter_dev","type":"dev_t","value":271581185},{"name":"ineterpreter_inode","type":"unsigned long","value":2752590},{"name":"sha256","type":"const char*","value":""}]}
    ```

    At the end of the event, you will also get information about the loader 

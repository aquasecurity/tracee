# Tracing Output Formats

In order to check latest output options you may execute:

```text
$ sudo ./dist/tracee-ebpf --output help
$ sudo ./dist/tracee-ebpf --output format:xxx
```

Tracee supports different output formats for detected events:

1. **Table**

    ```text
    $ sudo ./dist/tracee-ebpf --output table --trace comm=bash --trace follow --trace event=openat
    TIME             UID    COMM             PID     TID     RET              EVENT                ARGS
    11:21:51:254199  1000   exa              1639459 1639459 3                openat               dirfd: -100, pathname: /etc/ld.so.cache, flags: O_RDONLY|O_CLOEXEC, mode: 0
    11:21:51:254285  1000   exa              1639459 1639459 3                openat               dirfd: -100, pathname: /lib/x86_64-linux-gnu/libgcc_s.so.1, flags: O_RDONLY|O_CLOEXEC, mode: 0
    11:21:51:254418  1000   exa              1639459 1639459 3                openat               dirfd: -100, pathname: /lib/x86_64-linux-gnu/libm.so.6, flags: O_RDONLY|O_CLOEXEC, mode: 0
    
    End of events stream
    Stats: {EventCount:6 EventsFiltered:0 NetEvCount:0 ErrorCount:0 LostEvCount:0 LostWrCount:0 LostNtCount:0}
    ```

2. **Table (Verbose)**

    ```text
    $ sudo ./dist/tracee-ebpf --output table-verbose --trace comm=bash --trace follow --trace event=openat
    TIME             UTS_NAME         CONTAINER_ID  MNT_NS       PID_NS       UID    COMM             PID     TID     PPID    RET              EVENT                ARGS
    11:22:16:970700  fujitsu                        4026531840   4026531836   1000   exa              1643836 1643836 3795408 3                openat               dirfd: -100, pathname: /etc/ld.so.cache, flags: 524288, mode: 0
    11:22:16:970783  fujitsu                        4026531840   4026531836   1000   exa              1643836 1643836 3795408 3                openat               dirfd: -100, pathname: /lib/x86_64-linux-gnu/libgcc_s.so.1, flags: 524288, mode: 0
    11:22:16:970913  fujitsu                        4026531840   4026531836   1000   exa              1643836 1643836 3795408 3                openat               dirfd: -100, pathname: /lib/x86_64-linux-gnu/libm.so.6, flags: 524288, mode: 0
    
    End of events stream
    Stats: {EventCount:6 EventsFiltered:0 NetEvCount:0 ErrorCount:0 LostEvCount:0 LostWrCount:0 LostNtCount:0}
    ```

3. **JSON**

    ```text
    $ sudo ./dist/tracee-ebpf --output json --trace comm=bash --trace follow --trace event=openat
    ```

    ```json
    {"timestamp":1657290245020855990,"threadStartTime":615325807626168,"processorId":22,"processId":1664936,"cgroupId":1,"threadId":1664936,"parentProcessId":3795408,"hostProcessId":1664936,"hostThreadId":1664936,"hostParentProcessId":3795408,"userId":1000,"mountNamespace":4026531840,"pidNamespace":4026531836,"processName":"exa","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"257","eventName":"openat","argsNum":4,"returnValue":3,"stackAddresses":null,"args":[{"name":"dirfd","type":"int","value":-100},{"name":"pathname","type":"const char*","value":"/etc/ld.so.cache"},{"name":"flags","type":"int","value":524288},{"name":"mode","type":"mode_t","value":0}]}
    {"timestamp":1657290245020940791,"threadStartTime":615325807626168,"processorId":22,"processId":1664936,"cgroupId":1,"threadId":1664936,"parentProcessId":3795408,"hostProcessId":1664936,"hostThreadId":1664936,"hostParentProcessId":3795408,"userId":1000,"mountNamespace":4026531840,"pidNamespace":4026531836,"processName":"exa","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"257","eventName":"openat","argsNum":4,"returnValue":3,"stackAddresses":null,"args":[{"name":"dirfd","type":"int","value":-100},{"name":"pathname","type":"const char*","value":"/lib/x86_64-linux-gnu/libgcc_s.so.1"},{"name":"flags","type":"int","value":524288},{"name":"mode","type":"mode_t","value":0}]}
    ```
    
    !!! Tip
        A good tip is to pipe **tracee-ebpf** json output to [jq]() tool, this way
        you can select fields, rename them, filter values, and many other things:
        > ```text
        > sudo ./dist/tracee-ebpf -o format:json -o option:parse-arguments -o
        > option:detect-syscall -trace comm=ping -capture net=lo | jq -c '. |
        > {eventId, hostName,processName,hostProcessId,UserId}'
        > ```

4. **GOB**

    ```text
    $ sudo ./dist/tracee-ebpf --output json --trace comm=bash --trace follow --trace event=openat
    ```

    > The output is **binary** (optimizes performance when piping
    > **tracee-ebpf** events to **tracee-rules**, for signature patterns
    > detections).

5. **GOTEMPLATE**

    Check [integrations page](../integrating/go-templates.md) for more info.

## Output Files

Tracee gives user the option to select which files they want to use as standard
output and standard error:

1. Output file

    !!! tip
        User might use different output formats combined with output file option

    ```text
    $ sudo ./dist/tracee-ebpf --output json --trace comm=bash --trace follow --trace event=openat --output out-file:/tmp/tracee.log
    
    $ cat /tmp/tracee.log | jq -c
    ```

    ```json
    {"timestamp":1657291487418386000,"threadStartTime":616568205378363,"processorId":11,"processId":1893369,"cgroupId":1,"threadId":1893369,"parentProcessId":3795408,"hostProcessId":1893369,"hostThreadId":1893369,"hostParentProcessId":3795408,"userId":1000,"mountNamespace":4026531840,"pidNamespace":4026531836,"processName":"exa","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"257","eventName":"openat","argsNum":4,"returnValue":3,"stackAddresses":null,"args":[{"name":"dirfd","type":"int","value":-100},{"name":"pathname","type":"const char*","value":"/etc/ld.so.cache"},{"name":"flags","type":"int","value":524288},{"name":"mode","type":"mode_t","value":0}]}
    {"timestamp":1657291487418510000,"threadStartTime":616568205378363,"processorId":11,"processId":1893369,"cgroupId":1,"threadId":1893369,"parentProcessId":3795408,"hostProcessId":1893369,"hostThreadId":1893369,"hostParentProcessId":3795408,"userId":1000,"mountNamespace":4026531840,"pidNamespace":4026531836,"processName":"exa","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"257","eventName":"openat","argsNum":4,"returnValue":3,"stackAddresses":null,"args":[{"name":"dirfd","type":"int","value":-100},{"name":"pathname","type":"const char*","value":"/lib/x86_64-linux-gnu/libgcc_s.so.1"},{"name":"flags","type":"int","value":524288},{"name":"mode","type":"mode_t","value":0}]}
    ```

2. Error file

    Redirect errors to your log files if needed:

    ```text
    $ sudo TRACEE_BPF_FILE=do-not-exist ./dist/tracee-ebpf --output json --trace comm=bash --trace follow --trace event=openat --output out-file:/tmp/tracee.log --output err-file:/tmp/tracee.err
    ```

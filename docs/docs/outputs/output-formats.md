# Tracing Output Formats

The `--output` flag controls where and how Tracee will output events, by specifying `--output <format>:<destination>`.  You can use the `--output` flag multiple times to output events in multiple ways. To see all output options you can run `tracee --output help`.

The following output formats are supported:

- `table[:/path/to/file]` - output events in table format (default). The default path to file is stdout.
- `table-verbose[:/path/to/file]` - output events in table format with extra fields per event. The default path to file is stdout.
- `json[:/path/to/file]` - output events in json format. The default path to file is stdout.
- `gob[:/path/to/file]` - output events in gob format. The default path to file is stdout.
- `gotemplate=/path/to/template[:/path/to/file]` - output events formatted using a given gotemplate file. The default path to file is stdout.
- `forward:http://url/fluent` - send events in json format using the Forward protocol to a Fluent receiver
- `webhook:http://url/webhook` - send events in json format to the webhook url
- `none` - ignore stream of events output, usually used with --capture

## Examples

### Table

```console
sudo ./dist/tracee --output table --filter comm=bash --filter follow --filter event=openat
```

```text
TIME             UID    COMM             PID     TID     RET              EVENT                ARGS
11:21:51:254199  1000   exa              1639459 1639459 3                openat               dirfd: -100, pathname: /etc/ld.so.cache, flags: O_RDONLY|O_CLOEXEC, mode: 0
11:21:51:254285  1000   exa              1639459 1639459 3                openat               dirfd: -100, pathname: /lib/x86_64-linux-gnu/libgcc_s.so.1, flags: O_RDONLY|O_CLOEXEC, mode: 0
11:21:51:254418  1000   exa              1639459 1639459 3                openat               dirfd: -100, pathname: /lib/x86_64-linux-gnu/libm.so.6, flags: O_RDONLY|O_CLOEXEC, mode: 0

End of events stream
Stats: {EventCount:3 EventsFiltered:0 NetCapCount:0 BPFLogsCount:0 ErrorCount:0 LostEvCount:0 LostWrCount:0 LostNtCapCount:0 LostBPFLogsCount:0}
```

### Table (Verbose)

    ```console
    sudo ./dist/tracee --output table-verbose --filter comm=bash --filter follow --filter event=openat
    ```

    ```text
    TIME             UTS_NAME         CONTAINER_ID  MNT_NS       PID_NS       UID    COMM             PID     TID     PPID    RET              EVENT                ARGS
    11:22:16:970700  fujitsu                        4026531840   4026531836   1000   exa              1643836 1643836 3795408 3                openat               dirfd: -100, pathname: /etc/ld.so.cache, flags: 524288, mode: 0
    11:22:16:970783  fujitsu                        4026531840   4026531836   1000   exa              1643836 1643836 3795408 3                openat               dirfd: -100, pathname: /lib/x86_64-linux-gnu/libgcc_s.so.1, flags: 524288, mode: 0
    11:22:16:970913  fujitsu                        4026531840   4026531836   1000   exa              1643836 1643836 3795408 3                openat               dirfd: -100, pathname: /lib/x86_64-linux-gnu/libm.so.6, flags: 524288, mode: 0
    
    End of events stream
    Stats: {EventCount:3 EventsFiltered:0 NetCapCount:0 BPFLogsCount:0 ErrorCount:0 LostEvCount:0 LostWrCount:0 LostNtCapCount:0 LostBPFLogsCount:0}
    ```

### JSON

```console
sudo ./dist/tracee --output json --filter comm=bash --filter follow --filter event=openat
```

```json
{"timestamp":1657290245020855990,"threadStartTime":615325807626168,"processorId":22,"processId":1664936,"cgroupId":1,"threadId":1664936,"parentProcessId":3795408,"hostProcessId":1664936,"hostThreadId":1664936,"hostParentProcessId":3795408,"userId":1000,"mountNamespace":4026531840,"pidNamespace":4026531836,"processName":"exa","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"257","eventName":"openat","argsNum":4,"returnValue":3,"stackAddresses":null,"syscall":"openat","contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"dirfd","type":"int","value":-100},{"name":"pathname","type":"const char*","value":"/etc/ld.so.cache"},{"name":"flags","type":"int","value":524288},{"name":"mode","type":"mode_t","value":0}]}
{"timestamp":1657290245020940791,"threadStartTime":615325807626168,"processorId":22,"processId":1664936,"cgroupId":1,"threadId":1664936,"parentProcessId":3795408,"hostProcessId":1664936,"hostThreadId":1664936,"hostParentProcessId":3795408,"userId":1000,"mountNamespace":4026531840,"pidNamespace":4026531836,"processName":"exa","hostName":"fujitsu","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","eventId":"257","eventName":"openat","argsNum":4,"returnValue":3,"stackAddresses":null,"syscall":"openat","contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"dirfd","type":"int","value":-100},{"name":"pathname","type":"const char*","value":"/lib/x86_64-linux-gnu/libgcc_s.so.1"},{"name":"flags","type":"int","value":524288},{"name":"mode","type":"mode_t","value":0}]}
```

!!! Tip
    A good tip is to pipe **tracee** json output to [jq]() tool, this way
    you can select fields, rename them, filter values, and many other things:
    > ```console
    > sudo ./dist/tracee -o json -o option:parse-arguments
    > -trace comm=ping | jq -c '. | {eventId, hostName, processName,
    > hostProcessId,UserId}'
    > ```

### GOB

```console
sudo ./dist/tracee --output json --filter comm=bash --filter follow --filter event=openat
```

### GOTEMPLATE

When authoring a Go template the data source is Tracee's `trace.Event` struct, which is defined in `https://github.com/aquasecurity/tracee/blob/main/types/trace/trace.go#L15`.

Go template can utilize helper functions from [Sprig](http://masterminds.github.io/sprig/).

For example templates, see [tracee/cmd/tracee-rules/templates](https://github.com/aquasecurity/tracee/tree/main/cmd/tracee-rules/templates).

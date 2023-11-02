# Defining Tracee Logs

This section showcases how to configure diagnostics log. The information provided can then be used to troubleshoot Tracee. This is done through the Tracee configuration file. For more information, have a look at the respective section in the [installation guide.](../install/index.md)

## Log options

**Configure the log severity:**

```console
log:
    level: debug
    aggregate:
        enabled: true
```

Note that the other log level are `info`, `warn`, `error` and `panic`.

**Redirect logs to a file if needed:**

```console
log:
    level: debug
    aggregate:
        enabled: true
    file: "/tmp/tracee.log"
```

**Logs can be aggregated for a given interval to delay its output:**

```console
log:
    level: debug
    aggregate:
        flush-interval: "5s"
        
```

**Filter logs which message contains specified words:**

```console
log:
    filters: 
        msg: 
            - foo
            - bar
```

**Filter logs using regular expressions against messages:**

```console
log:
    filters: 
        regex: 
            - ^pattern-one
```

**Filter logs originating from a specific package:**

```console
log:
    filters: 
        pkg:
            - core
```

**Filter logs originating from a specific file:**

```console
log:
    filter: 
        file: 
            - /pkg/cmd/flags/logger.go
```

**Filter logs based on their severity level:**

```console
log:
    filters: 
        level: 
            - error
```

**Filter logs originating from libbpf**:

```console
log:
    filters: 
        libbpf: true
```

All `--log filter` options can also be used with `--log filter-out` for the opposite behavior. For more information, please refer to the `--log` help in the CLI.

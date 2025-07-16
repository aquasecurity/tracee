# Tracee Logs

This section showcases how to configure diagnostics log. The information provided can then be used to troubleshoot Tracee. This is done through the Tracee configuration file. For more information, have a look at the respective section in the [installation guide.](../install/index.md)

## Log options

**Configure the log severity:**

```console
log:
    level: debug
```

Note that the other log level are `info`, `warn`, `error` and `panic`.

**Redirect logs to a file if needed:**

```console
log:
    level: debug
    file: "/tmp/tracee.log"
```

**Logs can be aggregated for a given interval (default: 3s) to delay its output:**

```console
log:
    level: debug
    aggregate:
        enabled: true
        flush-interval: "10s"
```

The flush-interval defines how often the Tracee logs will be forwarded.

**Filter logs which message contains specified words:**

```console
log:
    filter: 
        include:
            msg: 
                - foo
                - bar
```

**Filter logs using regular expressions against messages:**

```console
log:
    filter: 
        include:
            regex: 
                - ^pattern-one
```

**Filter logs originating from a specific package:**

```console
log:
    filter: 
        include: 
            pkg:
                - core
```

**Filter logs originating from a specific file:**

```console
log:
    filter: 
        include: 
            file: 
                - /pkg/cmd/flags/logger.go
```

**Filter logs based on their severity level:**

```console
log:
    filter: 
        include: 
            level: 
                - error
```

**Filter logs originating from libbpf**:

```console
log:
    filter: 
        libbpf: true
```

## Additional Configuration

All `filter` options can also be used with `exclude` to achieve the opposite behavior. 

For instance, the following configuration would exclude all logs with the severity level `error`:

```console
log:
    filter: 
        exclude:
            level: 
                - error
```

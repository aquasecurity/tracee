# Tracee Logs

This section showcases how to configure diagnostic logs. The information provided can be used to troubleshoot Tracee.

For complete details on all logging options, see the [logging flag reference](../flags/logging.1.md).

## Configuration

### Log Level

Configure the log severity level:

**CLI:**
```console
tracee --logging level=debug
```

**Config file:**
```yaml
logging:
    level: debug
```

Available log levels: `debug`, `info` (default), `warn`, `error`, `fatal`

### Log File

Redirect logs to a file:

**CLI:**
```console
tracee --logging file=/tmp/tracee.log
```

**Config file:**
```yaml
logging:
    level: debug
    file: /tmp/tracee.log
```

### Log Aggregation

Aggregate logs for a given interval (default: 3s) to delay output:

**CLI:**
```console
tracee --logging aggregate --logging aggregate.flush-interval=10s
```

**Config file:**
```yaml
logging:
    aggregate:
        enabled: true
        flush-interval: 10s
```

The flush-interval defines how often Tracee logs will be forwarded.

## Log Filtering

### Filter by Message Content

Filter logs which message contains specified words:

**CLI:**
```console
tracee --logging filters.include.msg=foo,bar
```

**Config file:**
```yaml
logging:
    filters:
        include:
            msg: 
                - foo
                - bar
```

### Filter by Regular Expression

Filter logs using regular expressions against messages:

**CLI:**
```console
tracee --logging filters.include.regex='^pattern-one'
```

**Config file:**
```yaml
logging:
    filters:
        include:
            regex: 
                - ^pattern-one
```

### Filter by Package

Filter logs originating from a specific package:

**CLI:**
```console
tracee --logging filters.include.pkg=core
```

**Config file:**
```yaml
logging:
    filters:
        include: 
            pkg:
                - core
```

### Filter by File

Filter logs originating from a specific file:

**CLI:**
```console
tracee --logging filters.exclude.file=/pkg/cmd/flags/logger.go
```

**Config file:**
```yaml
logging:
    filters:
        include: 
            file: 
                - /pkg/cmd/flags/logger.go
```

### Filter by Log Level

Filter logs based on their severity level:

**CLI:**
```console
tracee --logging filters.include.level=error
```

**Config file:**
```yaml
logging:
    filters:
        include: 
            level:
                - error
```

### Filter libbpf Logs

Filter logs originating from libbpf:

**CLI:**
```console
tracee --logging filters.include.libbpf
```

**Config file:**
```yaml
logging:
    filters:
        include:
            libbpf: true
```

## Include vs Exclude

All `filters` options can be used with either `include` or `exclude` to achieve opposite behavior.

**Include example** - only show error logs:
```yaml
logging:
    filters:
        include:
            level:
                - error
```

**Exclude example** - hide error logs:
```yaml
logging:
    filters:
        exclude:
            level:
                - error
```

You can combine include and exclude filters to create complex filtering rules. For more examples, see the [logging flag reference](../flags/logging.1.md).

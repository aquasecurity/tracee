---
title: TRACEE-LOG
section: 1
header: Tracee Log Flag Manual
date: 2025/03
...

## NAME

tracee **\-\-log** - Control logger options - aggregation and level priority

## SYNOPSIS

tracee **\-\-log** aggregate.flush-interval=<time\>| aggregate.enable=<true|false\> | level=<debug|info|warn|error|fatal\> | file=/path/to/file | filters.include.[msg=<value,...\>] | filters.include.[regex=<value,...\>] | filters.include.[pkg=<value,...\>] | filters.include.[file=<value,...\>] | filters.include.[level=<value,...\>] | filters.include.[libbpf] | filters.exclude.[msg=<value,...\>] | filters.exclude.[regex=<value,...\>] | filters.exclude.[pkg=<value,...\>] | filters.exclude.[file=<value,...\>] | filters.exclude.[level=<value,...\>] | filters.exclude.[libbpf]


## DESCRIPTION

The **\-\-log** flag allows you to control logger options for the tool.

Possible log options:

- **aggregate.flush-interval=[time] | aggregate.enable=[true|false]**: Turns log aggregation on, delaying output with an optional interval (default: 3s). The flush-interval can be specified in seconds (s) or minutes (m).

- **level=<debug|info|warn|error|fatal\>**: Sets the log level. The default log level is 'info'.

- **file=/path/to/file**: Writes the logs to the specified file. If the file exists, it will be created or trimmed.

- **filters.include.**<option;...\>: Filters in logs that match the specified option values. Multiple filter options can be provided, separated by semicolons.

- **filters.exclude.**<option;...\>: Filters out logs that match the specified option values. Multiple filter options can be provided, separated by semicolons.

Filter options:

- **msg=<value,...\>**: Filters logs that have the message containing any of the specified values.

- **regex=<value,...\>**: Filters logs that match the specified regular expression in the message.

- **pkg=<value,...\>**: Filters logs that originate from the specified package.

- **file=<value,...\>**: Filters logs that originate from the specified file.

- **level=<value,...\>**: Filters logs that are of the specified level.

- **libbpf**: Filters logs that originate from libbpf.

## EXAMPLES

- To output debug level logs, use the following flag:

  ```console
  --log level=debug
  ```

- To output aggregated debug level logs every 3 seconds (default), use the following flag:

  ```console
  --log level=debug --log aggregate.enable=true
  ```

- To output aggregated logs every 5 seconds, use the following flag:

  ```console
  --log aggregate.flush-interval=5s
  ```

- To output debug level logs to `/tmp/tracee.log`, use the following flag:

  ```console
  --log level=debug --log file=/tmp/tracee.log
  ```

- To filter in logs that have either 'foo' or 'bar' in the message, are from the 'core' package, and are of 'error' level, use the following flag:

  ```console
  --log filters.include.msg=foo,bar --log filters.include.pkg=core --log filters.include.level=error
  ```

- To filter out logs that have either 'foo' or 'bar' in the message, are from the 'core' package, and are of 'error' level, use the following flag:

  ```console
  --log filters.exclude.msg=foo,bar --log filters.exclude.pkg=core --log filters.exclude.level=error
  ```

- To filter in logs that have either 'foo' or 'bar' in the message and, based on that result, filter out logs that are from the 'core' package, use the following flag:

  ```console
  --log filters.include.msg=foo,bar --log filters.exclude.pkg=core
  ```

- To filter out logs that originate from the '/pkg/cmd/flags/logger.go' file, use the following flag:

  ```console
  --log filters.exclude.file=/pkg/cmd/flags/logger.go
  ```

- To filter in logs that have messages matching the regex '^foo', use the following flag:

  ```console
  --log filters.include.regex='^foo'
  ```

- To filter in logs that originate from libbpf, use the following flag:

  ```console
  --log filters.include.libbpf
  ```

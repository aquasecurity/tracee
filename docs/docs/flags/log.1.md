---
title: TRACEE-LOG
section: 1
header: Tracee Log Flag Manual
date: 2023/10
...

## NAME

tracee **\-\-log** - Control logger options - aggregation and level priority

## SYNOPSIS

tracee **\-\-log** aggregate[:flush-interval] | <debug|info|warn|error|panic\> | file:/path/to/file | filter:[msg=<value,...\>;regex=<value,...\>;pkg=<value,...\>;file=<value,...\>;lvl=<value,...\>;libbpf] | filter-out:[msg=<value,...\>;regex=<value,...\>;pkg=<value,...\>;file=<value,...\>;lvl=<value,...\>;libbpf]

## DESCRIPTION

The **\-\-log** flag allows you to control logger options for the tool.

Possible log options:

- **aggregate[:flush-interval]**: Turns log aggregation on, delaying output with an optional interval (default: 3s). The flush-interval can be specified in seconds (s) or minutes (m).

- **<debug|info|warn|error|panic\>**: Sets the log level. The default log level is 'info'.

- **file:/path/to/file**: Writes the logs to the specified file. If the file exists, it will be created or trimmed.

- **filter:**<option;...\>: Filters in logs that match the specified option values. Multiple filter options can be provided, separated by semicolons.

- **filter-out:**<option;...\>: Filters out logs that match the specified option values. Multiple filter options can be provided, separated by semicolons.

Filter options:

- **msg=<value,...\>**: Filters logs that have the message containing any of the specified values.

- **regex=<value,...\>**: Filters logs that match the specified regular expression in the message.

- **pkg=<value,...\>**: Filters logs that originate from the specified package.

- **file=<value,...\>**: Filters logs that originate from the specified file.

- **lvl=<value,...\>**: Filters logs that are of the specified level.

- **libbpf**: Filters logs that originate from libbpf.

## EXAMPLES

- To output debug level logs, use the following flag:

  ```console
  --log debug
  ```

- To output aggregated debug level logs every 3 seconds (default), use the following flag:

  ```console
  --log debug --log aggregate
  ```

- To output aggregated logs every 5 seconds, use the following flag:

  ```console
  --log aggregate:5s
  ```

- To output debug level logs to `/tmp/tracee.log`, use the following flag:

  ```console
  --log debug --log file:/tmp/tracee.log
  ```

- To filter in logs that have either 'foo' or 'bar' in the message, are from the 'core' package, and are of 'error' level, use the following flag:

  ```console
  --log filter:'msg=foo,bar;pkg=core;lvl=error'
  ```

- To filter out logs that have either 'foo' or 'bar' in the message, are from the 'core' package, and are of 'error' level, use the following flag:

  ```console
  --log filter-out:'msg=foo,bar;pkg=core;lvl=error'
  ```

- To filter in logs that have either 'foo' or 'bar' in the message and, based on that result, filter out logs that are from the 'core' package, use the following flag:

  ```console
  --log filter:msg=foo,bar --log filter-out:pkg=core
  ```

- To filter out logs that originate from the '/pkg/cmd/flags/logger.go' file, use the following flag:

  ```console
  --log filter-out:file=/pkg/cmd/flags/logger.go
  ```

- To filter in logs that have messages matching the regex '^foo', use the following flag:

  ```console
  --log filter:regex='^foo'
  ```

- To filter in logs that originate from libbpf, use the following flag:

  ```console
  --log filter:libbpf
  ```

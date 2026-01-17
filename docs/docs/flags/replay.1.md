---
title: TRACEE-REPLAY
section: 1
header: Tracee Replay Command Manual
date: 2025/01
...

## NAME

tracee **replay** - Replay past events from a file and process them with detectors

## SYNOPSIS

tracee **replay** \<file\> [options]

## DESCRIPTION

The **replay** command allows you to replay past events from a file and process them with detectors. This is useful for analyzing historical event data, testing detector configurations, and debugging detector behavior.

**Important**: Only low-level events should be replayed. Detector events (high-level events) are automatically filtered out during replay.

## ARGUMENTS

**file**
: Path to the event file to replay. The file should contain events in JSON Lines format (one JSON event per line), as produced by tracee with `--output json:file.json`.

## OPTIONS

**\-\-output**, **\-o** \<format\>[:path]
: Control how and where output is printed. Format can be `json`, `table`, `webhook`, etc. Path is optional and defaults to `stdout` for most formats.

  **Note**: Replay mode currently supports a single output destination at a time. If multiple output streams or destinations are configured, only the first destination from the first stream will be used. All other outputs will be ignored.

  Examples:
  - `--output json:stdout` - JSON format to stdout
  - `--output table` - Table format to stdout
  - `--output json:output.json` - JSON format to file
  - `--output webhook:http://localhost:8080` - Send to webhook

**\-\-detectors** [path...]
: Configure YAML detector search directories or files. Can be specified multiple times to search multiple directories or files.

  Examples:
  - `--detectors /etc/tracee/detectors`
  - `--detectors /path/to/detectors --detectors /another/path`
  - `--detectors /path/to/detector.yaml`

**\-\-log**, **\-l** \<level\>[:destination]
: Logger options. Level can be `debug`, `info`, `warn`, `error`. Destination is optional.

  Examples:
  - `--log debug` - Debug level logging
  - `--log info:stdout` - Info level to stdout

## ARCHITECTURE

### Event Filtering

The replay command automatically filters out detector events (high-level events) from the input file. Only low-level events are replayed.

## EXAMPLES

### Basic Replay

Replay events from a file with default settings:

```console
tracee replay events.json
```

### Replay with Table Output

Replay events and display results in table format:

```console
tracee replay events.json --output table
```

### Replay with Custom Detectors

Replay events using detectors from a custom directory:

```console
tracee replay events.json --detectors /path/to/detectors
```

### Replay with Debug Logging

Replay events with debug-level logging:

```console
tracee replay events.json --log debug
```

### Complete Example

Capture events, then replay them:

```console
# Capture events to file
tracee --events execve,openat --output json:events.json

# Replay events with detectors
tracee replay events.json --output table --detectors /etc/tracee/detectors --log info
```

## FILE FORMAT

The replay file should contain events in JSON Lines format (one JSON event per line). Each line should be a valid JSON object representing a `v1beta1.Event` protobuf message in JSON format.

Example file content:

```json
{"timestamp":"2024-01-01T00:00:00Z","id":1,"name":"execve","workload":{"process":{"executable":{"path":"/bin/bash"}}}}
{"timestamp":"2024-01-01T00:00:01Z","id":2,"name":"openat","workload":{"process":{"executable":{"path":"/bin/bash"}}}}
```

## NOTES

- Detector events in the input file will be automatically filtered out with a warning message
- Only low-level events are processed
- Events are processed in file order

## SEE ALSO

- **tracee(1)** - Main tracee command
- **tracee-list(1)** - List available events, detectors, and policies
- **Detector Documentation**: See [YAML Detectors](../detectors/yaml-detectors.md)

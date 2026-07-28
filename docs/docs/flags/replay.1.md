---
title: TRACEE-REPLAY
section: 1
header: Tracee Replay Command Manual
date: 2026/07
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

  **Note**: Replay mode currently supports a single output destination at a time. Configuring multiple output streams or destinations is rejected with an error.

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

**\-\-logging**, **\-l** \<option\>
: Logger options. Use `level=<level>` where level is `debug`, `info`, `warn`, `error` or `fatal` (default `info`), and `file=<path>` to write logs to a file (default stderr).

  Examples:
  - `--logging level=debug` - Debug level logging
  - `--logging level=info --logging file=/var/log/tracee.log` - Info level to a file

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
tracee replay events.json --logging level=debug
```

### Complete Example

Capture events, then replay them:

```console
# Capture events to file
tracee --events execve,openat --output json:events.json

# Replay events with detectors
tracee replay events.json --output table --detectors /etc/tracee/detectors --logging level=info
```

## FILE FORMAT

The replay file should contain events in JSON Lines format (one JSON event per line). Each line should be a valid JSON object representing a `v1beta1.Event` protobuf message in JSON format.

Events are dispatched by the numeric `id` (the protobuf `EventId` enum value, e.g. `60` for `execve`, `258` for `openat`); the `name` field is informational.

Example file content:

```json
{"timestamp":"2024-01-01T00:00:00Z","id":60,"name":"execve","workload":{"process":{"executable":{"path":"/bin/bash"}}}}
{"timestamp":"2024-01-01T00:00:01Z","id":258,"name":"openat","workload":{"process":{"executable":{"path":"/bin/bash"}}}}
```

## NOTES

- Detector events in the input file are automatically filtered out
- Only low-level events are processed
- Events are processed in file order

## SEE ALSO

- **tracee(1)** - Main tracee command
- **tracee-list(1)** - List available events, detectors, and policies
- **Detector Documentation**: See [YAML Detectors](../detectors/yaml-detectors.md)

# Tracee Output

Tracee can generate thousands of events per day depending on your system and policies. The output system provides flexible ways to format, filter, route, and store these events for analysis and integration with your monitoring stack.

## Overview

The output system consists of several components that work together to control how Tracee events are handled:

- **Formats**: Choose how events are serialized (JSON, table, custom templates)
- **Destinations**: Route events to files, webhooks, or forward to log aggregators
- **Streams**: Create filtered event pipelines with independent routing
- **Options**: Enrich events with additional context (stack traces, environment variables, etc.)
- **Logging**: Configure Tracee's diagnostic logs separate from event output

## Configuration

Output is configured using the `--output` flag or the `output:` section in your configuration file. For complete details, see the [output flag reference](../flags/output.1.md).

**Basic CLI example:**
```console
tracee --output destinations.stdout_json.format=json
```

**Configuration file example:**
```yaml
output:
  destinations:
    - name: json_file
      type: file
      format: json
      path: /var/log/tracee/events.json
  options:
    parse-arguments: true
```

## Output Components

### [Destinations](../flags/output.1.md)

Route events to different outputs. Tracee supports three destination types:

- **File**: Write to files or stdout/stderr
- **Webhook**: Send events to HTTP endpoints
- **Forward**: Stream to FluentBit/Fluentd receivers

Each destination is configured with a type, format, and path or URL.

### [Formats](./output-formats.md)

Control how events are serialized and presented:

- **JSON**: Machine-readable format for log aggregation and SIEM integration
- **Table**: Human-readable terminal output for debugging and development
- **Go Templates**: Custom formatting using Go template syntax

### [Streams](./streams.md)

Create multiple output pipelines with independent filtering and routing. Streams allow you to:

- Route different events to different destinations
- Apply policy-based filtering
- Configure separate buffering strategies

### [Event Structure](./event-structure.md)

Understand the structure and fields available in Tracee events for parsing and analysis.

### [Sorting Events](./sorting-events.md)

Learn about event ordering guarantees and how to enable chronological sorting when needed.

### [Options](./output-options.md)

Enrich events with additional context:

- `parse-arguments`: Convert raw values to human-readable format
- `parse-arguments-fds`: Show file paths for file descriptor arguments
- `stack-addresses`: Include stack traces in events
- `exec-env`: Include environment variables for process execution events
- `exec-hash`: Include file hashes for executed binaries
- `sort-events`: Enable chronological event ordering

### [Logging](./logging.md)

Configure Tracee's diagnostic logs (separate from event output) for troubleshooting and monitoring Tracee itself.

## Quick Start Examples

**JSON output to file:**
```console
tracee --output destinations.file_out.format=json --output destinations.file_out.path=/var/log/tracee.json
```

**Default table output with parsed arguments:**
```console
tracee --enrichment parse-arguments
```

**Send events to webhook:**
```console
tracee --output destinations.webhook1.type=webhook --output destinations.webhook1.url=http://my-webhook:8080
```

**Multiple destinations with streams:**
```yaml
output:
  destinations:
    - name: all_events
      type: file
      format: json
      path: /var/log/tracee/all.json
    - name: security_events
      type: webhook
      url: https://siem.example.com/events
  streams:
    - name: security_stream
      destinations:
        - security_events
      filters:
        events:
          - security_file_open
          - security_socket_connect
```

## Additional Resources

- [Output flag reference](../flags/output.1.md): Complete CLI flag documentation
- [Example configurations](https://github.com/aquasecurity/tracee/blob/main/examples/config/global_config.yaml): Sample configuration files
- [Configuration guide](../install/config/index.md): General configuration documentation
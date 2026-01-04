# Output Formats

Configure how Tracee events are serialized and displayed. Each destination can use a different format.

## Overview

Tracee supports three output formats:

- **JSON** - Machine-readable format for log aggregation and SIEM integration
- **Table** - Human-readable terminal output for debugging and development
- **Go Template** - Custom formatting using Go template syntax for flexible output

The format is configured per destination. See the [output flag reference](../flags/output.1.md) for complete destination configuration.

## Format Types

### JSON

JSON format outputs events as structured JSON objects, one per line. This is the recommended format for production use, log aggregation, and integration with monitoring tools.

**Example configuration:**

```yaml
output:
  destinations:
    - name: json_out
      format: json
      path: /var/log/tracee/events.json
```

**CLI:**

```bash
tracee --output destinations.json_out.format=json
```

**Use cases:**
- Integration with SIEM systems (Splunk, Elasticsearch, etc.)
- Structured logging for analysis
- Machine parsing and automation

!!! Tip
    Pipe JSON output to [jq](https://jqlang.github.io/jq/) for powerful filtering and transformation:
    ```bash
    tracee --output destinations.stdout.format=json | jq '.name'
    ```

### Table

Table format provides human-readable output formatted as a table in the terminal. This is the **default format** for file destinations when no format is specified.

**Example configuration:**

```yaml
output:
  destinations:
    - name: table_out
      format: table
```

**CLI:**

```bash
tracee --output destinations.table_out.format=table
```

**Use cases:**
- Interactive debugging and development
- Quick manual inspection of events
- Terminal-based monitoring

### Go Template

Go template format allows complete control over output formatting using Go's template syntax. Templates access Tracee's `v1beta1.Event` protobuf structure.

**Example configuration:**

```yaml
output:
  destinations:
    - name: custom_out
      format: gotemplate=/path/to/template.tmpl
      path: /var/log/tracee/custom.log
```

**CLI:**

```bash
tracee --output destinations.custom_out.format=gotemplate=/path/to/template.tmpl
```

#### Template Data Structure

Templates have access to the complete `v1beta1.Event` protobuf structure defined in the [API protobuf definitions](https://github.com/aquasecurity/tracee/blob/main/api/v1beta1/event.proto).

**Common event fields:**

| Field | Description |
|-------|-------------|
| `.timestamp` | Event timestamp (`.seconds` and `.nanos`) |
| `.id` | Event ID (protobuf enum) |
| `.name` | Event name (string) |
| `.policies.matched` | Array of matched policy names |
| `.workload.process.thread.name` | Process/thread name |
| `.workload.process.pid.value` | Process ID |
| `.workload.process.real_user.id.value` | User ID |
| `.workload.process.executable.path` | Executable path |
| `.data` | Array of event-specific data fields |
| `.threat` | Threat information (for detections) |

**For detection events:**

| Field | Description |
|-------|-------------|
| `.threat.name` | Threat/signature name |
| `.threat.description` | Threat description |
| `.threat.properties.signatureID` | Signature ID |
| `.detected_from` | Underlying event that triggered detection |

#### Template Functions

Go templates support helper functions from [Sprig](http://masterminds.github.io/sprig/) for string manipulation, formatting, and more.

**Example template:**

```go
{% raw %}
{{- range . -}}
Time: {{ .timestamp.seconds }} | Event: {{ .name }} | PID: {{ .workload.process.pid.value }}
{{- end }}
{% endraw %}
```

**Use cases:**
- Custom log formats for specific tools
- Simplified output with only needed fields
- Integration with legacy systems requiring specific formats

## Format Per Destination

Different destinations can use different formats in the same configuration:

```yaml
output:
  destinations:
    - name: json_file
      type: file
      format: json
      path: /var/log/tracee/events.json

    - name: table_console
      type: file
      format: table
      path: stdout

    - name: webhook
      type: webhook
      format: gotemplate=/etc/tracee/webhook.tmpl
      url: https://siem.example.com/events
```

## Default Format

The default format depends on the destination type:

| Destination Type | Default Format |
|------------------|----------------|
| `file` | `table` |
| `webhook` | `json` |
| `forward` | `json` |

## See Also

- [Output Flag Reference](../flags/output.1.md) - Complete destination configuration
- [Output Overview](./index.md) - Output system overview
- [Streams](./streams.md) - Filter and route events to different destinations
- [Event Structure](./event-structure.md) - Understanding event fields
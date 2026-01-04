---
title: TRACEE-CONFIG
section: 1
header: Tracee Config Flag Manual
date: 2025/01
...

## NAME

tracee **\-\-config** - Define global configuration options for tracee

## SYNOPSIS

tracee **\-\-config** <file\>

## DESCRIPTION

The **\-\-config** flag allows you to specify global configuration options for Tracee by providing a configuration file.

The configuration file supports both structured (nested) and flat (CLI-style) formats, and can include settings for all Tracee subsystems including output formats, event filters, enrichment options, buffers, logging, and more.

## FILE FORMAT

The configuration file supports multiple formats:

- **YAML**: Recommended format with clear hierarchy and comments support
- **JSON**: Standard JSON format for programmatic generation

## USAGE

To use the **\-\-config** flag, you need to provide the path to the configuration file:

```console
tracee --config /path/to/tracee-config.yaml
```

## EXAMPLES

### Nested (Structured) Format

Example configuration file using nested YAML structure:

```yaml
output:
  destinations:
    - name: stdout_destination
      type: file
      format: json
      path: stdout

logging:
  level: info

enrichment:
  container:
    enabled: true

buffers:
  kernel:
    events: 2048
    artifacts: 1024
  pipeline: 10000

server:
  http-address: ":3366"
  metrics: true
  healthz: true
```

### CLI-Style (Flat) Format

The same configuration using CLI-style flat format:

```yaml
output.destinations.stdout_destination.type: file
output.destinations.stdout_destination.format: json
output.destinations.stdout_destination.path: stdout
logging.level: info
enrichment.container.enabled: true
buffers.kernel.events: 2048
buffers.kernel.artifacts: 1024
buffers.pipeline: 10000
server.http-address: ":3366"
server.metrics: true
server.healthz: true
```

For a complete example configuration file with all available options, see:
https://github.com/aquasecurity/tracee/blob/main/examples/config/global_config.yaml

## SEE ALSO

For more detailed information about configuration:

- **Configuration Guide**: See the [Configuration Overview](../install/config/index.md)
- **Kubernetes Configuration**: See the [Kubernetes Configuration Guide](../install/config/kubernetes.md)

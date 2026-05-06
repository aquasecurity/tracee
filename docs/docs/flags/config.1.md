---
title: TRACEE-CONFIG
section: 1
header: Tracee Config Flag Manual
date: 2026/05
...

## NAME

tracee **\-\-config** - Define global configuration options for tracee

## SYNOPSIS

tracee **\-\-config** <file\>

## DESCRIPTION

The **\-\-config** flag allows you to specify global configuration options for Tracee by providing a configuration file.

The configuration file supports structured (nested) YAML under each top-level key, or a list of CLI-style flag strings under that same key. Dotted keys at the root of the file (for example `server.http-address`) are not loaded; each subsystem must appear as its own top-level key (`server`, `output`, `logging`, and so on).

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

### CLI-Style (List) Format

The same configuration using CLI-style lists under each top-level key. Each entry is one flag string, like on the command line.

```yaml
output:
  - destinations.stdout_destination.type=file
  - destinations.stdout_destination.format=json
  - destinations.stdout_destination.path=stdout

logging:
  - level=info

enrichment:
  - container

buffers:
  - kernel.events=2048
  - kernel.artifacts=1024
  - pipeline=10000

server:
  - "http-address=:3366"
  - metrics
  - healthz
```

For a complete example configuration file with all available options, see:
https://github.com/aquasecurity/tracee/blob/main/examples/config/global_config.yaml

## NOTES

The following options are **not** supported in the configuration file and must be
provided exclusively via the CLI:

- **\-\-config**: Path to the config file itself.
- **\-\-policy**: Policy file or directory paths.
- **\-\-scope**: Scope filters.
- **\-\-events**: Event filters.

Policies can also be supplied through Kubernetes CRDs when running in a cluster.

## SEE ALSO

For more detailed information about configuration:

- **Configuration Guide**: See the [Configuration Overview](../install/config/index.md)
- **Kubernetes Configuration**: See the [Kubernetes Configuration Guide](../install/config/kubernetes.md)

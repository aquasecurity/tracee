# Tracee Configuration file

Below are the configurable flags and their options for Tracee. You can set these flags directly when running Tracee or through a configuration file (YAML or JSON).

### Scope Flags

- **`--scope` (`-s`)**: Defines which workloads to trace by specifying filter expressions.
  
  Example usage:
  ```bash
  tracee --scope uid=1000,1001
  ```

  YAML:
  ```yaml
  scope:
    - uid=1000,1001
  ```

  JSON:
  ```json
  {
    "scope": ["uid=1000,1001"]
  }
  ```

### Event Flags

- **`--events` (`-e`)**: Selects specific events to trace, and allows filtering by event attributes.

  Example usage:
  ```bash
  tracee --events name=open,execve
  ```

  YAML:
  ```yaml
  events:
    - open
    - execve
  ```

  JSON:
  ```json
  {
    "events": ["open", "execve"]
  }
  ```
  __NOTE__: you can view all compatible events in the [event section](../../events/index.md)

### Policy Flags

- **`--policy` (`-p`)**: Specifies a policy file or directory of policies that define what to trace.

  Example usage:
  ```bash
  tracee --policy` /path/to/policy.yaml
  ```

  YAML:
  ```yaml
  policy:
    - /path/to/policy.yaml
  ```

  JSON:
  ```json
  {
    "policy": ["/path/to/policy.yaml"]
  }
  ```
  __NOTE__: you can view policies in the [policy section](../../policies/index.md)

### Output Flags

- **`--output` (`-o`)**: Controls how and where the output is printed.

  Supported options: `json`, `none`, `webhook`, `table`(default)

  Example usage:
  ```bash
  tracee --output json
  ```

  YAML:
  ```yaml
  output:
    - json
  ```

  JSON:
  ```json
  {
    "output": ["json"]
  }
  ```
  __NOTE__: you can view all outputs in the [output section](../../outputs/index.md)

### Capture Flags

- **`--capture` (`-c`)**: Captures artifacts such as files or network packets that are written or executed.

   Supported options: `write` , `exec` , `network`

  Example usage:
  ```bash
  tracee --capture write
  ```

  YAML:
  ```yaml
  capture:
    - write
  ```

  JSON:
  ```json
  {
    "capture": ["write"]
  }
  ```

### Container Flags

- **`--no-containers`**: Disables container information enrichment in events.

  Example usage:
  ```bash
  tracee --no-containers
  ```

  YAML:
  ```yaml
  no-containers: true
  ```

  JSON:
  ```json
  {
    "no-containers": true
  }
  ```

- **`--cri`**: Defines connected container runtimes in the format `<runtime:socket>`.

  Example usage:
  ```bash
  tracee --cri docker:/var/run/docker.sock
  ```

  YAML:
  ```yaml
  cri:
    - docker:/var/run/docker.sock
  ```

  JSON:
  ```json
  {
    "cri": ["docker:/var/run/docker.sock"]
  }
  ```

### Signature Flags

- **`--signatures-dir`**: Specifies directories to search for signatures in OPA (`.rego`) or Go plugin (`.so`) formats.

  Example usage:
  ```bash
  tracee --signatures-dir /path/to/signatures
  ```

  YAML:
  ```yaml
  signatures-dir:
    - /path/to/signatures
  ```

  JSON:
  ```json
  {
    "signatures-dir": ["/path/to/signatures"]
  }
  ```

- **`--rego`**: Controls Rego signature evaluation settings.

  Example usage:
  ```bash
  tracee --rego aio
  ```

  YAML:
  ```yaml
  rego:
    - aio
  ```

  JSON:
  ```json
  {
    "rego": ["aio"]
  }
  ```

### Buffer and Cache Flags

- **`--perf-buffer-size` (`-b`)**: Specifies the size of the internal perf ring buffer in pages.

  Default: `1024` (4 MB)

  Example usage:
  ```bash
  tracee --perf-buffer-size 2048
  ```

  YAML:
  ```yaml
  perf-buffer-size: 2048
  ```

  JSON:
  ```json
  {
    "perf-buffer-size": 2048
  }
  ```
- **`--blob-perf-buffer-size`**: Specifies the size of the internal perf ring buffer used to send blobs from the kernel.

  Default: `1024` (4 MB)

  Example usage:
  ```bash
  tracee --blob-perf-buffer-size 2048
  ```

  YAML:
  ```yaml
  blob-perf-buffer-size: 2048
  ```

  JSON:
  ```json
  {
    "blob-perf-buffer-size": 2048
  }
  ```
- **`--pipeline-channel-size`**: Specifies the size of each pipeline stage's output channel.
  Default: `10000` 

  Example usage:
  ```bash
  tracee --pipeline-channel-size 2048
  ```

  YAML:
  ```yaml
  pipeline-channel-size: 2048
  ```

  JSON:
  ```json
  {
    "pipeline-channel-size": 2048
  }
  ```

- **`--cache` (`-a`)**: Controls event caching options.

  Example usage:
  ```bash
  tracee --cache mem-cache-size=512
  ```

  YAML:
  ```yaml
  cache:
    - mem-cache-size=512
  ```

  JSON:
  ```json
  {
    "cache": ["mem-cache-size=512"]
  }
  ```

### Process Tree Flags

- **`--proctree` (`-t`)**: Controls process tree options.

  Example usage:
  ```bash
  tracee --proctree process
  ```

  YAML:
  ```yaml
  proctree:
    - process
  ```

  JSON:
  ```json
  {
    "proctree": ["process"]
  }
  ```

### DNS Cache

- **`--dnscache`**: Enables DNS caching in Tracee.

  Example usage:
  ```bash
  tracee --dnscache
  ```

  YAML:
  ```yaml
  dnscache: enable
  ```

  JSON:
  ```json
  {
    "dnscache": enable
  }
  ```

### Server Flags

- **`--metrics-endpoint`**: Enables the metrics endpoint.

  Example usage:
  ```bash
  tracee --metrics-endpoint
  ```

  YAML:
  ```yaml
  metrics-endpoint: true
  ```

  JSON:
  ```json
  {
    "metrics-endpoint": true
  }
  ```

- **`--grpc-listen-addr`**: Specifies the address for the gRPC server.
  Example usage:
  ```bash
  tracee --grpc-listen-addr tcp:0.0.0.0:50051
  ```

  YAML:
  ```yaml
  grpc-listen-addr: tcp:0.0.0.0:50051
  ```

  JSON:
  ```json
  {
    "grpc-listen-addr": "tcp:0.0.0.0:50051"
  }
  ```


### Capabilities Flags

- **`--capabilities` (`-C`)**: Define specific capabilities for Tracee to run with. This allows you to either bypass, add, or drop certain capabilities based on your security and operational needs.

  Supported options: `bypass`, `add`, `drop`

  Example usage:
  ```bash
  tracee --capabilities add=CAP_SYS_ADMIN,drop=CAP_NET_RAW
  ```

  YAML:
  ```yaml
  capabilities:
    - add: CAP_SYS_ADMIN
    - drop: CAP_NET_RAW
  ```

  JSON:
  ```json
  {
    "capabilities": [
      {"add": "CAP_SYS_ADMIN"},
      {"drop": "CAP_NET_RAW"}
    ]
  }
  ```

  __NOTE__: Capabilities are Linux-specific permissions that control which privileged operations a program can perform. Tracee can add or drop these capabilities based on your configuration. Using `bypass` allows Tracee to run without making any changes to its default capabilities.

### Install Path Flag

- **`--install-path`**: Specifies the directory where Tracee will install or look for its resources. If not specified, the default installation directory is `/tmp/tracee`.

  Example usage:
  ```bash
  tracee --install-path /opt/tracee
  ```

  YAML:
  ```yaml
  install-path: /opt/tracee
  ```

  JSON:
  ```json
  {
    "install-path": "/opt/tracee"
  }
  ```

  __NOTE__: This option is useful when running Tracee in environments where `/tmp` is not suitable or secure, allowing you to set a custom installation directory.

### Log Flags

- **`--log` (`-l`)**: Controls the verbosity level of Tracee's logging system. Multiple logging options can be defined to filter specific log levels. The default log level is `info`.

  Supported options: `debug`, `info`, `warn`, `error`

  Example usage:
  ```bash
  tracee --log debug,info
  ```

  YAML:
  ```yaml
  log:
    - debug
    - info
  ```

  JSON:
  ```json
  {
    "log": ["debug", "info"]
  }
  ```

  __NOTE__: Setting log levels is crucial for monitoring Tracee's behavior, especially in debugging and troubleshooting scenarios. The `debug` level provides the most detailed logging, while `info`, `warn`, and `error` reduce verbosity.

## Full Example of a Configuration File

Here’s a full example of what a configuration file might look like in YAML:

```yaml
scope:
  - uid=1000
events:
  - execve
  - open
output:
  - json
capture:
  - write
cri:
  - docker:/var/run/docker.sock
log:
  - debug
```

And the equivalent in JSON:

```json
{
  "scope": ["uid=1000"],
  "events": ["execve", "open"],
  "output": ["json"],
  "capture": ["write"],
  "cri": ["docker:/var/run/docker.sock"],
  "log": ["debug"]
}
```

And the equivalent in CLI flags:
```bash
tracee --scope uid=1000 \
       --events name=execve,open \
       --output json \
       --capture write \
       --cri docker:/var/run/docker.sock \
       --log debug
```
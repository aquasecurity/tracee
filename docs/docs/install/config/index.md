# Configuring Tracee

Tracee has many different options and settings that control how Tracee operates. 


To learn about how to apply configuration to Tracee, please refer to the [CLI](./cli.md) or [Kubernetes](./kubernetes.md) specific guides, depending on how you deploy Tracee.

A complete config file with all available options can be found [here](https://github.com/aquasecurity/tracee/blob/main/examples/config/global_config.yaml). Most of the options are documented in different sections in the documentation.

  - __NOTE__: The YAML examples can be translated to JSON as well

## Common configurations


### Output

- **`--output` (`-o`)**: Controls how and where the output is printed.

  __NOTE__: You can view more in the [output section](../../outputs/index.md).

  YAML:
  ```yaml
  output:
    - json
  ```


### Server

- __`--server`__: Sets options for the HTTP and/or gRPC servers.

  CLI Examples:
  ```bash
  # Address configuration
  tracee --server http-address=:3366
  tracee --server grpc-address=unix:/var/run/tracee.sock

  # HTTP features (boolean flags)
  tracee --server metrics --server healthz --server pprof
  ```

  YAML:
  ```yaml
  server:
    http-address: ":3366"
    grpc-address: "unix:/var/run/tracee.sock"
    metrics: true
    healthz: true
    pprof: true
    pyroscope: true
  ```

### Process Tree

- **`--proctree` (`-t`)**: Controls process tree options.


  __NOTE__: You can view more in the [Process Tree section](../../advanced/data-sources/builtin/process-tree.md).

  YAML:
  ```yaml
  proctree:
    - process
  ```

### Install Path

- **`--install-path`**: Specifies the directory where Tracee will install or look for its resources. If not specified, the default installation directory is `/tmp/tracee`.

  YAML:
  ```yaml
  install-path: /opt/tracee
  ```

  __NOTE__: This option is useful when running Tracee in environments where `/tmp` is not suitable or secure.

### Log

- **`--log` (`-l`)**: Controls the verbosity level of Tracee's logging system. The default log level is `info`.


  __NOTE__: You can view more in the [Tracee Logs section](../../outputs/logging.md).

  YAML:
  ```yaml
  log:
    - level: debug
  ```

### Containers

- To disable container enrichment use: **`--enrich container.enabled=false`**.

  YAML:
  ```yaml
  enrich:
    container:
      enabled: false
  ```

  __NOTE__: You can view more in the [enrich section](../../flags/enrich.1.md).

- **`--enrich`**: Configures enrichment options including container enrichment and runtime sockets. For example, to configure runtime sockets:

  YAML:
  ```yaml
  enrich:
    container:
      docker:
        socket: /var/run/docker.sock
  ```

### DNS Cache

- **`--dnscache`**: Enables DNS caching in Tracee.

  __NOTE__: You can view more in the [DNS Cache section](../../advanced/data-sources/builtin/dns.md). 

  YAML:
  ```yaml
  dnscache: enable
  ```

### Capabilities

- **`--capabilities` (`-C`)**: Define specific capabilities for Tracee to run with. This allows you to either bypass, add, or drop certain capabilities based on your security and operational needs.

    
  __NOTE__: You can view more in the [Tracee Capabilities section](../../flags/capabilities.1.md)

  YAML:
  ```yaml
  capabilities:
    - add: 
        - CAP_SYS_ADMIN
    - drop: 
        - CAP_NET_RAW
  ```

  __NOTE__: Capabilities are Linux-specific permissions that control which privileged operations a program can perform.



### Buffer and Cache

- **`--perf-buffer-size` (`-b`)**: Specifies the size of the internal perf ring buffer in pages.

  Default: `1024` (4 MB)

  YAML:
  ```yaml
  perf-buffer-size: 2048
  ```

- **`--blob-perf-buffer-size`**: Specifies the size of the internal perf ring buffer used to send blobs from the kernel.

  Default: `1024` (4 MB)

  YAML:
  ```yaml
  blob-perf-buffer-size: 2048
  ```

- **`--pipeline-channel-size`**: Specifies the size of each pipeline stage's output channel.

  Default: `1000`

  YAML:
  ```yaml
  pipeline-channel-size: 2048
  ```

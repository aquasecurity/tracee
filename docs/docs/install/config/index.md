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

- **`--buffers`**: Configures the buffer sizes for kernel and user buffers.

  Buffer sizes for perf ring buffers (kernel-events, kernel-blob, control-plane-events) are specified in pages. The pipeline buffer size is specified in event objects. The default size for perf ring buffers is 1024 pages. The default size for the pipeline buffer is 10000 event objects.

  YAML:
  ```yaml
  buffers:
      kernel-events: 2048
      kernel-blob: 1024
      control-plane-events: 512
      pipeline: 20000
  ```

  CLI:
  ```bash
  --buffers kernel-events=2048 --buffers kernel-blob=1024 --buffers control-plane-events=512 --buffers pipeline=20000
  ```

  __NOTE__: You can view more in the [buffers section](../../flags/buffers.1.md).

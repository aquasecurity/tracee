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

### Stores (Process Tree and DNS Cache)

- **`--stores`**: Controls process tree and DNS cache options.


  __NOTE__: You can view more in the [Process Tree section](../../advanced/data-sources/builtin/process-tree.md) and [DNS Cache section](../../advanced/data-sources/builtin/dns.md).

  YAML:
  ```yaml
  stores:
    process:
      enabled: true
      source: both
    dns:
      enabled: true
  ```

### Runtime

- **`--runtime` (`-r`)**: Controls runtime configurations for Tracee.

  CLI Examples:
  ```bash
  # Set working directory
  tracee --runtime workdir=/opt/tracee
  ```

  YAML:
  ```yaml
  runtime:
    - workdir=/opt/tracee
  ```

  __NOTE__: The workdir is the path where Tracee will install or lookup its resources. The default is `/tmp/tracee`. This option is useful when running Tracee in environments where `/tmp` is not suitable or secure.

### Log

- **`--logging` (`-l`)**: Controls Tracee logging options, like verbosity,
filters, destination file and others.


  __NOTE__: You can view more in the [Tracee Logs section](../../outputs/logging.md).

  YAML:
  ```yaml
  log:
    - level: debug
  ```

### Containers

- To enable container enrichment, include the flag: **`--enrichment container`**. To disable it, simply omit the flag. Note: Setting any container sub-option (e.g., `container.docker.socket=/path`) automatically enables container, so `--enrichment container` is not needed.

  YAML:
  ```yaml
  enrichment:
    container:
      enabled: true
  ```

  __NOTE__: You can view more in the [enrichment section](../../flags/enrichment.1.md).

- **`--enrichment`**: Configures enrichment options including container enrichment and runtime sockets. For example, to configure runtime sockets:

  YAML:
  ```yaml
  enrichment:
    container:
      enabled: true
      cgroupfs:
        path: /host/sys/fs/cgroup
        force: false
      docker-socket: /var/run/docker.sock
      containerd-socket: /var/run/containerd/containerd.sock
      crio-socket: /var/run/crio/crio.sock
      podman-socket: /var/run/podman/podman.sock
    resolve-fd: true
    exec-hash:
      enabled: true
      mode: sha256
    user-stack-trace: true
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

  Buffer sizes for perf ring buffers (kernel.events, kernel.artifacts, kernel.control-plane) are specified in pages. The pipeline buffer size is specified in event objects. The default size for perf ring buffers is 1024 pages. The default size for the pipeline buffer is 1000 event objects.

  YAML:
  ```yaml
  buffers:
      kernel:
          events: 2048
          artifacts: 1024
          control-plane: 512
      pipeline: 20000
  ```

  CLI:
  ```bash
  --buffers kernel.events=2048 --buffers kernel.artifacts=1024 --buffers kernel.control-plane=512 --buffers pipeline=20000
  ```

  __NOTE__: You can view more in the [buffers section](../../flags/buffers.1.md).

# CLI Policy Usage

This section details how to use the flags in the Tracee CLI.

## Applying Tracee Polcies

A [policy file](../index.md) can be applied in the Tracee command using the `--policy` flag and providing a path to the location of the policy file.

```console
tracee --policy ./policy.yml
```

## Using multiple policies

To specify multiple policies, users can either specify the directory, which contains all of the policies that they would like to load into Tracee, or by specifying the policies one by one.

Through a directory:

```console
tracee --policy ./policy-directory
```

By specifying individual policies:

```console
tracee --policy ./policy-one.yaml --policy ./policy-two.yaml 
```

## EXAMPLE

```console
tracee --config ./config.yaml --policy ./policy.yaml && cat /tmp/debug.json
```

### config.yaml (example)

```yaml
install-path: /tmp/tracee

# debugging

healthz: true
metrics: false
pprof: false
pyroscope: false
listen-addr: :3366

# feature flags

no-containers: false
blob-perf-buffer-size: 1024

# signatures

rego: []
signatures-dir: ""

# features setup

capabilities:
    bypass: false
cache:
    type: mem
    size: 512
proctree:
    source: both
    cache:
        process: 8192
        thread: 8192
# cri:
#     - runtime:
#         name: docker
#         socket: /var/run/docker.sock

# logging

log:
    level: debug
    file: /tmp/debug.json
    # aggregate:
    #     enabled: true
    #     flush-interval: 5s
    filters:
        out:
            pkg:
                - capabilities
# output

output:
    options:
        none: false
        stack-addresses: false
        exec-env: true
        relative-time: true
        exec-hash: dev-inode
        parse-arguments: true
        parse-arguments-fds: true
        sort-events: true
    json:
        files:
            - stdout
    forward: []
    webhook: []
```

### policy.yaml

```yaml
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: signatures
  annotations:
    description: traces all signatures
spec:
  scope:
    - global
  rules:
    # display security events
    - event: stdio_over_socket
    - event: k8s_api_connection
    - event: aslr_inspection
    - event: proc_mem_code_injection
    - event: docker_abuse
    - event: scheduled_task_mod
    - event: ld_preload
    - event: cgroup_notify_on_release
    - event: default_loader_mod
    - event: sudoers_modification
    - event: sched_debug_recon
    - event: system_request_key_mod
    - event: cgroup_release_agent
    - event: rcd_modification
    - event: core_pattern_modification
    - event: proc_kcore_read
    - event: proc_mem_access
    - event: hidden_file_created
    - event: anti_debugging
    - event: ptrace_code_injection
    - event: process_vm_write_inject
    - event: disk_mount
    - event: dynamic_code_loading
    - event: fileless_execution
    - event: illegitimate_shell
    - event: kernel_module_loading
    - event: k8s_cert_theft
    - event: proc_fops_hooking
    - event: syscall_hooking
    - event: dropped_executable
    # tracee open by cat in /tmp/* files
    - event: openat
      filters:
        - comm=cat
        - args.pathname=/tmp*
    # trace all container creations and removals
    - event: container_create
    - event: container_remove
```

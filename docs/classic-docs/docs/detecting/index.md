# Getting Started with Detecting

Tracee is a **runtime security detection engine**, more than an introspection
tool (**tracee-ebpf**) only. **tracee-rules** is a **rules engine** that helps
you detect **suspicious behavioral patterns** in streams of events. It is
primarily made to leverage events collected with **tracee-ebpf** into a
**Runtime Security solution**.

!!! Attention
    You may sometimes read **rules** or **signatures**. Both mean the same
    thing for tracee: a set of expressions that will define whether there
    was a security event detection or not.

There are 3 basic concepts for **tracee-rules**:

1. **Inputs** - Event sources to be processed.
    1. **tracee-ebpf** only current supported source

2. **Rules (a.k.a Signatures)** - behavioral pattern to detect from the input
   source. Signatures can be authored in:
    1. **Golang** (high performance, more error prone)
    2. **Rego (OPA)** (high level declarative language)
    3. **Go-Cel** *(tech-preview)* (good performance, simple)

3. **Outputs** - How to communicate detections:
    1. Print to stdout
    2. Post to a webhook
    3. Integrate with external systems

## Getting Started

**tracee-rules** doesn't have any requirement, but in order to run with
**tracee-ebpf**, make sure you follow the **tracee-ebpf** [prerequisites].

[prerequisites]: ../../../getting-started/installing/prerequisites.md

!!! Attention
    You can't customize (yet) **tracee-rules** execution when executing
    official **tracee container**. The official container is configured with a
    pre-set of signatures already enabled by default. In order to customize it
    you have to follow [building/containers.md] instructions and change the
    default entrypoint and signatures.

[building/containers.md]: ../../../contributing/building/containers.md

Check [getting tracee] in order to understand how to obtain **tracee-rules**.

[getting tracee]: ../../../getting-started/installing/getting.md

### Running **tracee-rules**

1. Running **tracee-rules** with **trace-ebpf** in the simplest possible way:

     ```bash
     sudo ./dist/tracee-ebpf \
         -o format:gob \
         | tracee-rules \
         --input-tracee file:stdin \
         --input-tracee format:gob
     ```

     This will:
     
     1. Start **tracee-ebpf** with the default filtering mode (default events).
     2. Configure **tracee-ebpf** to output events into stdout as [gob] format.
     3. Start **tracee-rules** with all built-in signatures enabled.

[gob]:https://golang.org/pkg/encoding/gob/

1. A more realistic example

!!! Example
    Let's put together all that we learned from the [tracing] section, together
    with what we're learning at this section and see how we can filter events
    and pipe them to **tracee-rules** so detections occur:
     
     [tracing]:../tracing/index.md
     
     ```text
     $ sudo ./dist/tracee-ebpf \
         --output json \
         --filter comm=bash \
         --filter follow \
         --output option:parse-arguments \
         --filter event=$(./dist/tracee-rules --list-events) \
         | ./dist/tracee-rules \
         --input-tracee format:json \
         --input-tracee file:stdin
     
     Loaded 14 signature(s): [TRC-1 TRC-13 TRC-2 TRC-14 TRC-3 TRC-11 TRC-9 TRC-4 TRC-5 TRC-12 TRC-6 TRC-10 TRC-7 TRC-15]
     ```
     
     We are:

     1. **filtering all executed commands** from all existing and new `bash` processes,
     1. **detecting syscalls** that generated each event (if they're not syscalls),
     1. **parsing captured event** arguments into a human readable format,
     1. **filtering for ALL events needed by all existing signatures**,
     1. **detecting behaviors** described in all existing and loaded **tracee-rules** signatures.

## Selecting Signatures

When executing **tracee-rules**, you're able to select which signatures you
would like it to load. Also, in order to make **tracee-ebpf** only trace for
meaningful events (for the loaded signature(s)) you may request from
**tracee-rules** which events are needed for the selected signatures.

1. **List default (all) signatures**

    ```text
    $ ./dist/tracee-rules --list
    Loaded 14 signature(s): [TRC-1 TRC-13 TRC-2 TRC-14 TRC-3 TRC-11 TRC-9 TRC-4 TRC-5 TRC-12 TRC-6 TRC-10 TRC-7 TRC-15]
    ID         NAME                                VERSION DESCRIPTION
    TRC-1      Standard Input/Output Over Socket   0.1.0   Redirection of process's standard input/output to socket
    TRC-13     Kubernetes API server connection detected 0.1.0   A connection to the kubernetes API server was detected. The K8S API server is the brain of your K8S cluster, adversaries may try and communicate with the K8S API server to gather information/credentials, or even run more containers and laterally expand their grip on your systems.
    TRC-2      Anti-Debugging                      0.1.0   Process uses anti-debugging technique to block debugger
    TRC-14     CGroups Release Agent File Modification 0.1.0   An Attempt to modify CGroups release agent file was detected. CGroups are a Linux kernel feature which can change a process's resource limitations. Adversaries may use this feature for container escaping.
    TRC-3      Code injection                      0.1.0   Possible code injection into another process
    TRC-11     Container Device Mount Detected     0.1.0   Container device filesystem mount detected. A mount of a host device filesystem can be exploited by adversaries to perform container escape.
    TRC-9      New Executable Was Dropped During Runtime 0.1.0   An Executable file was dropped in your system during runtime. Usually container images are built with all binaries needed inside, a dropped binary may indicate an adversary infiltrated into your container.
    TRC-4      Dynamic Code Loading                0.1.0   Writing to executable allocated memory region
    TRC-5      Fileless Execution                  0.1.0   Executing a process from memory, without a file in the disk
    TRC-12     Illegitimate Shell                  0.1.0   A program on your server spawned a shell program. Shell is the linux command-line program, server programs usually don't run shell programs, so this alert might indicate an adversary is exploiting a server program to spawn a shell on your server.
    TRC-6      kernel module loading               0.1.0   Attempt to load a kernel module detection
    TRC-10     K8S TLS Certificate Theft Detected  0.1.0   Kubernetes TLS certificate theft was detected. TLS certificates are used to establish trust between systems, the kubernetes certificate is used to to enable secured communication between kubernetes components, like the kubelet, scheduler, controller and API server. An adversary may steal a kubernetes certificate on a compromised system to impersonate kubernetes components within the cluster.
    TRC-7      LD_PRELOAD                          0.1.0   Usage of LD_PRELOAD to allow hooks on process
    TRC-15     Hooking system calls by overriding the system call table entries 0.1.0   Usage of kernel modules to hook system calls
    ```

1. **List events needed** by default (all) signatures

    ```text
    $ ./dist/tracee-rules --list-events
    close,dup,dup2,dup3,execve,hooked_syscalls,init_module,magic_write,mem_prot_alert,process_vm_writev,ptrace,sched_process_exec,sched_process_exit,security_bprm_check,security_file_open,security_kernel_read_file,security_sb_mount,security_socket_connect
    ```

1. **List events** needed for **given signatures only**

    !!! Tip
        If we chose to load a single signature, we can ask **tracee-rules** to
        give us the events needed by that signature. This will allow
        **tracee-ebpf** to just listen to those events.

    ```text
    $ ./dist/tracee-rules --rules TRC-3 --list-events
    process_vm_writev,ptrace,security_file_open
    ```

## Tracing with Selected Signatures

!!! Example
    Let's pretend we would like to pick TRC-2 signature only and monitor all
    new processes happening as children of all running `bash` processes.

    ```text
    $ sudo ./dist/tracee-ebpf --output json --filter comm=bash --filter follow --output option:parse-arguments --output option:exec-env --filter event=$(./dist/tracee-rules --rules TRC-2 --list-events) | ./dist/tracee-rules --input-tracee format:json --input-tracee file:stdin --rules TRC-2
    Loaded 1 signature(s): [TRC-2]
    
    *** Detection ***
    Time: 2022-07-09T21:42:45Z
    Signature ID: TRC-2
    Signature: Anti-Debugging
    Data: map[]
    Command: strace
    Hostname: fujitsu
    ```


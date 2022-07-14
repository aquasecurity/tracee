# Available Rules

!!! Tip
    To view the list of available rules, run Tracee with the `--list` flag.

Tracee currently distributes **fully functional signatures**, such as:

Name   |Description                               |Full Description
-------|------------------------------------------|----
TRC-1  |Standard Input/Output Over Socket         | Redirection of process's standard input/output to socket
TRC-2  |Anti-Debugging                            | Process uses anti-debugging technique to block debugger
TRC-3  |Code injection                            | Possible code injection into another process
TRC-4  |Dynamic Code Loading                      | Writing to executable allocated memory region
TRC-5  |Fileless Execution                        | Executing a process from memory, without a file in the disk
TRC-6  |kernel module loading                     | Attempt to load a kernel module detection
TRC-7  |LD_PRELOAD                                | Usage of LD_PRELOAD to allow hooks on process
TRC-9  |New Executable Was Dropped During Runtime | An Executable file was dropped in your system during runtime. Usually container images are built with all binaries needed inside, a dropped binary may indicate an adversary infiltrated into your container.
TRC-10 |K8S TLS Certificate Theft Detected        | Kubernetes TLS certificate theft was detected. TLS certificates are used to establish trust between systems, the kubernetes certificate is used to to enable secured communication between kubernetes components, like the kubelet, scheduler, controller and API server. An adversary may steal a kubernetes certificate on a compromised system to impersonate kuberentes components within the cluster.
TRC-11 |Container Device Mount Detected           | Container device filesystem mount detected. A mount of a host device filesystem can be exploited by adversaries to perform container escape.
TRC-12 |Illegitimate Shell                        | A program on your server spawned a shell program. Shell is the linux command-line program, server programs usually don't run shell programs, so this alert might indicate an adversary is exploiting a server program to spawn a shell on your server.
TRC-13 |Kubernetes API server connection detected | A connection to the kubernetes API server was detected. The K8S API server is the brain of your K8S cluster, adversaries may try and communicate with the K8S API server to gather information/credentials, or even run more containers and laterally expand their grip on your systems.
TRC-14 |CGroups Release Agent File Modification   | An Attempt to modify CGroups release agent file was detected. CGroups are a Linux kernel feature which can change a process's resource limitations. Adversaries may use this feature for container escaping.
TRC-15 |Override system call table entries        | Usage of kernel modules to hook system calls

!!! Note
    And, obviously, you can create your signatures in [golang], [rego] and [go-cel].

[golang]: ./golang.md
[rego]: ./rego.md
[go-cel]: ./go-cel.md

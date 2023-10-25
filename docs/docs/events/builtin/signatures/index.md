
# Security Events

## Understanding Signatures in Tracee

In Tracee, a signature is a set of criteria designed to detect specific system
activities based on events such as syscalls, network interactions, and LSM hook
occurrences. When these foundational system events align with the conditions set
by a signature, Tracee generates a corresponding "security event." This process
enables Tracee to actively monitor and report potential security concerns
arising from observed system interactions.

## Functionality and Scope of Signatures

The signatures documented herein focus on key system operations. For instance,
one signature identifies attempts to manipulate the syscall tables or the
`/proc` filesystem, operations that are indicative of rootkit behaviors. Another
detects the dynamic introduction of new executables into the system, flagging
potential security issues. Upon a match, these signatures prompt Tracee to
produce a security event, capturing the specifics of the underlying event and
any associated implications.

## The Role of Security Events in Tracee

Security events play a critical role in maintaining system integrity. They
provide an analytical layer, translating raw events like syscalls into
actionable insights about potential threats or anomalies. With the power of
eBPF, Tracee efficiently monitors system activities in real-time, generating
security events that equip users with the information they need to assess and
respond to the state of their digital environments.

## Be Prepared!

For optimal utilization of Tracee and effective response to potential threats,
we strongly recommend readers to meticulously review each security event
documentation page.

A good understanding of what each signature detects will empower users to make
informed decisions and take appropriate actions when a security event arises.
Being well-versed in the nuances of each signature ensures that you're not just
alerted to risks, but also equipped to address them effectively.

## List of Default Security Events

| Name of Signature                                        | Description                                    |
|----------------------------------------------------------|------------------------------------------------|
| [Anti-Debugging Technique](anti_debugging.md)            | Detects anti-debugging techniques.             |
| [ASLR Inspection](aslr_inspection.md)                    | Detects ASLR inspections.                      |
| [Cgroups notify_on_release File Modification](cgroup_notify_on_release_modification.md) | Monitors `notify_on_release` file changes in cgroups.|
| [Cgroups Release Agent File Modification](cgroup_release_agent_modification.md) | Detects changes to the cgroup release_agent.  |
| [Core Dumps Config File Modification](core_pattern_modification.md) | Monitors core dump configuration alterations. |
| [Default Dynamic Loader Modification](default_loader_modification.md) | Tracks changes to the default binary loader.   |
| [Container Device Mount](disk_mount.md)                  | Detects unauthorized container device mounts.  |
| [Docker Socket Abuse](docker_abuse.md)                   | Flags potential Docker socket misuse.          |
| [Dropped Executables](dropped_executable.md)             | Detects runtime-dropped executables.           |
| [Dynamic Code Loading](dynamic_code_loading.md)          | Monitors dynamic code loading events.          |
| [Fileless Execution](fileless_execution.md)              | Flags fileless execution techniques.           |
| [Hidden Executable File Creation](hidden_file_created.md)| Detects creation of hidden executable files.   |
| [Illegitimate Shell](illegitimate_shell.md)              | Flags unauthorized or unexpected shell executions.|
| [Kernel Module Loading](kernel_module_loading.md)        | Monitors kernel module load events.            |
| [Kubernetes API Server Connection](kubernetes_api_connection.md) | Detects connections to the Kubernetes API server. |
| [Kubernetes TLS Certificate Theft](kubernetes_certificate_theft_attempt.md) | Flags potential theft of Kubernetes certificates.|
| [LD_PRELOAD Code Injection](ld_preload.md)               | Monitors LD_PRELOAD injection attempts.        |
| [File Operations Hooking on Proc Filesystem](proc_fops_hooking.md) | Detects hooks on file operations in /proc.     |
| [Kcore Memory File Read](proc_kcore_read.md)             | Monitors reads of /proc/kcore.                 |
| [Process Memory Access](proc_mem_access.md)              | Flags unauthorized /proc/mem access.           |
| [Procfs Mem Code Injection](proc_mem_code_injection.md)  | Detects code injections via /proc/mem.         |
| [Process VM Write Code Injection](process_vm_write_code_injection.md) | Monitors injections via process_vm_writev.     |
| [Ptrace Code Injection](ptrace_code_injection.md)        | Detects ptrace-facilitated code injections.    |
| [RCD Modification](rcd_modification.md)                  | Monitors changes to the remote control daemon. |
| [Sched Debug Reconnaissance](sched_debug_recon.md)       | Flags /proc/sched_debug reconnaissance.        |
| [Scheduled Tasks Modification](scheduled_task_modification.md) | Tracks modifications to scheduled tasks.      |
| [Process Standard Input/Output over Socket](stdio_over_socket.md) | Detects IO redirection over sockets.          |
| [Sudoers File Modification](sudoers_modification.md)     | Monitors alterations to the sudoers file.      |
| [Syscall Table Hooking](syscall_table_hooking.md)        | Detects syscall table hook attempts.           |
| [System Request Key Configuration Modification](system_request_key_config_modification.md) | Monitors system request key configuration changes.|

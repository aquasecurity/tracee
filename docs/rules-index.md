# Available Rules

To view the list of available rules, run Tracee with the `--list` flag.

We are currently working on creating a library of behavioral signature detections. Currently, the following are available:

| Name | Description | Tags
| --- | --- | --- |
Standard Input/Output Over Socket | Redirection of process's standard input/output to socket | "linux", "container"
Anti-Debugging | Process uses anti-debugging technique to block debugger | "linux", "container"
Code injection | Possible code injection into another process | "linux", "container"
CGroups Release Agent File Modification | Attempts to modify Cgroups release agent file, which can change a process's resource limitations | "linux", "container"
Dynamic Code Loading | Writing to executable allocated memory region | "linux", "container"
Fileless Execution | Executing a process from memory, without a file in the disk | "linux", "container"
kernel module loading | Attempt to load a kernel module detection | "linux", "container"
LD_PRELOAD | Usage of LD_PRELOAD to allow hooks on process | "linux", "container"
Container Host Mount | Mounting of the host filesystem into a container | "container"
Dropped Executable | Creation or dropping of an executable file from a container at runtime | "linux", "container"
Illegitimate Shell | Spawning of a shell program | "linux", "container"
K8S API Connection | Connection to the Kubernetes cluster API server | "container"
K8S Service Account Use | Reading of the Kubernetes service account token file in a container | "container"
K8S TLS Certificate Theft | Accessing of the TLS certificate used for secure communication between Kubernetes components | "linux", "container"
System Call Table Entry Override | Usage of kernel modules to hook system calls | "linux"
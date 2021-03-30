# Available Rules

To view the list of available rules, run Tracee with the `--list` flag.

We are currently working on creating a library of behavioral signature detections. Currently, the following are available:

| Name | Description | Tags
| --- | --- | --- |
Standard Input/Output Over Socket | Redirection of process's standard input/output to socket | "linux", "container"
Anti-Debugging | Process uses anti-debugging technique to block debugger | "linux", "container"
Code injection | Possible code injection into another process | "linux", "container"
Dynamic Code Loading | Writing to executable allocated memory region | "linux", "container"
Fileless Execution | Executing a process from memory, without a file in the disk | "linux", "container"
kernel module loading | Attempt to load a kernel module detection | "linux", "container"
LD_PRELOAD | Usage of LD_PRELOAD to allow hooks on process | "linux", "container"

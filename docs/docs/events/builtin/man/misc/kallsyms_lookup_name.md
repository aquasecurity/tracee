---
title: TRACEE-KALLSYMS-LOOKUP-NAME
section: 1
header: Tracee Event Manual
---

## NAME

**kallsyms_lookup_name** - kernel symbol address lookup

## DESCRIPTION

Triggered when the `kallsyms_lookup_name()` kernel function is called to look up the address of a kernel symbol. This function is primarily used by external kernel extensions such as kernel modules, eBPF programs, and other kernel-level code that needs to resolve symbol addresses dynamically.

Monitoring symbol lookups can reveal potentially suspicious activity, such as rootkits or malicious kernel modules attempting to locate and hook kernel functions, or legitimate kernel extensions resolving symbol addresses for their operations.

## EVENT SETS

**none**

## DATA FIELDS

**symbol_name** (*string*)
: The name of the kernel symbol being looked up

**symbol_address** (*trace.Pointer*)
: The resolved address of the symbol returned by the function (0 if symbol not found)

## DEPENDENCIES

**Kernel Probes:**

- kallsyms_lookup_name (kprobe + kretprobe, required): Hooks the kernel symbol lookup function on entry and exit

## USE CASES

- **Security monitoring**: Detect attempts to locate sensitive kernel symbols for malicious purposes

- **Rootkit detection**: Identify malicious kernel modules looking up symbols for function hooking

- **Kernel debugging**: Monitor symbol resolution during kernel development and debugging

- **System analysis**: Understand kernel extension behavior and dependencies

- **Forensic analysis**: Track symbol lookup patterns during incident investigation

## COMMON SYMBOL LOOKUPS

Legitimate kernel extensions often look up:

- **System call table symbols**: For syscall interception or monitoring
- **VFS operation symbols**: For filesystem operation hooking
- **Network stack symbols**: For network monitoring or filtering
- **Security framework symbols**: For security policy enforcement
- **Hardware abstraction symbols**: For device driver functionality

## SUSPICIOUS PATTERNS

Monitor for lookups of sensitive symbols:

- **sys_call_table**: System call table (common rootkit target)
- **security_* functions**: Security framework functions
- **do_exit**, **do_fork**: Process lifecycle functions
- **vfs_* functions**: Virtual filesystem operations
- **network stack functions**: Network monitoring points

## SYMBOL RESOLUTION PROCESS

The `kallsyms_lookup_name` function:

1. **Searches symbol table**: Looks through the kernel symbol table
2. **Name matching**: Performs string comparison for symbol name
3. **Address resolution**: Returns the memory address if found
4. **Permission checking**: May verify caller permissions for sensitive symbols

## SECURITY IMPLICATIONS

Symbol address knowledge enables:

- **Function hooking**: Redirecting function calls to malicious code
- **Data structure access**: Direct manipulation of kernel data structures
- **Control flow hijacking**: Altering kernel execution flow
- **Information disclosure**: Bypassing kernel address space layout randomization (KASLR)

## LEGITIMATE USE CASES

- **Device drivers**: Hardware abstraction and device management
- **Security modules**: LSM implementations and security frameworks
- **Debugging tools**: Kernel debuggers and profiling tools
- **Virtualization**: Hypervisor and container runtime components
- **Monitoring tools**: System monitoring and observability frameworks

## RELATED EVENTS

- **module_load**: Kernel module loading events
- **init_module**: Module initialization system call
- **symbols_loaded**: Symbol loading in user-space libraries
- **shared_object_loaded**: Shared library loading events
---
title: TRACEE-SUSPICIOUS-SYSCALL-SOURCE
section: 1
header: Tracee Event Manual
---

## NAME

**suspicious_syscall_source** - syscall invoked from unusual code location

## DESCRIPTION

Triggered when a system call is invoked from an unusual code location that is not in a dedicated code region (VMA - Virtual Memory Area) mapped from executable files. This event detects potential code injection, shellcode execution, or other malicious activities where code is executed from unexpected memory locations.

Normally, all legitimate code runs from dedicated code regions mapped from executable files. When syscalls are invoked from stack, heap, or anonymous memory regions, it often indicates malicious activity such as shellcode execution or code injection attacks.

## EVENT SETS

**derived**, **security_alert**

## DATA FIELDS

**syscall** (*int32*)
: The system call number invoked from the unusual location (parsed to name if parse-arguments enabled)

**ip** (*trace.Pointer*)
: The instruction pointer address from which the syscall was invoked

**vma_type** (*string*)
: Description of the VMA type containing the code that triggered the syscall

**vma_start** (*trace.Pointer*)
: Start address of the VMA containing the triggering code

**vma_size** (*uint64*)
: Size of the VMA containing the triggering code

**vma_flags** (*uint64*)
: VMA flags (parsed to names if parse-arguments enabled)

## DEPENDENCIES

**Kernel Probes:**

- Individual syscall kprobes (configurable): Placed on selected syscalls for analysis

## CONFIGURATION

Use event parameters to specify which syscalls to monitor:

```bash
tracee --events suspicious_syscall_source.args.syscall=open,openat
```

## USE CASES

- **Shellcode detection**: Identify execution of injected shellcode from memory

- **Exploit detection**: Detect code injection and ROP/JOP attacks

- **Malware analysis**: Identify malicious code execution patterns

- **Security monitoring**: Detect unusual code execution locations

- **Incident response**: Investigate code injection during security incidents

## SUSPICIOUS SCENARIOS

Common scenarios triggering this event:

- **Stack-based shellcode**: Code execution from stack memory
- **Heap-based shellcode**: Code execution from heap allocations
- **Anonymous memory execution**: Code in non-file-backed memory regions
- **Packed executables**: Self-modifying or dynamically unpacked code
- **JIT compilation**: Just-in-time compiled code (may be legitimate)

## PERFORMANCE OPTIMIZATION

- **Selective monitoring**: Use syscall parameters to monitor specific syscalls only
- **Deduplication**: Unique combinations of process, syscall, and VMA reported only once
- **Overhead reduction**: Focuses on specified syscalls rather than all syscalls

## FALSE POSITIVES

Legitimate scenarios that may trigger this event:

- **JIT compilers**: Languages like Java, .NET, JavaScript with JIT compilation
- **Dynamic code generation**: Legitimate applications generating code at runtime
- **Packed executables**: Legitimate software using code packing/compression
- **Self-modifying code**: Some legitimate applications modify their own code

## MITIGATION STRATEGIES

- **DEP/NX bit**: Hardware-based execution prevention for data pages
- **ASLR**: Address Space Layout Randomization to complicate exploitation
- **CFI**: Control Flow Integrity to prevent ROP/JOP attacks
- **Stack canaries**: Detection of stack-based buffer overflows

## ANALYSIS TECHNIQUES

When investigating detections:

1. **VMA analysis**: Examine the memory region type and permissions
2. **Process context**: Check if the process is known to use JIT or dynamic code
3. **Syscall patterns**: Analyze which syscalls are being invoked unusually
4. **Timeline analysis**: Correlate with other suspicious activities

## RELATED EVENTS

- **process_vm_write_code_injection**: Direct code injection detection
- **ptrace_code_injection**: Ptrace-based code injection
- **mem_prot_alert**: Memory protection violations
- **stack_pivot**: Stack manipulation detection
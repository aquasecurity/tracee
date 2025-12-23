# Tracee's Security Model

## Introduction

Understanding Tracee's security model is essential for setting proper expectations about what Tracee can and cannot protect against. This document describes Tracee's adversary model, security boundaries, detection capabilities, and limitations to help you make informed decisions about deploying and using Tracee in your security infrastructure.

Tracee is an eBPF-based runtime security tool designed to detect threats and suspicious behavior by monitoring kernel events. However, like any security tool, it operates under specific assumptions and has inherent limitations based on its architecture and the adversary it targets.

## Core Security Assumptions

Tracee's security model is built on one fundamental assumption:

**The kernel is trusted when Tracee starts.**

This means:

- The kernel has not been compromised before Tracee loads its eBPF programs
- No kernel rootkits or malicious kernel modules are already present
- The kernel's integrity is intact at Tracee startup time

If this assumption is violated (i.e., the kernel is already compromised), Tracee's detection capabilities cannot be guaranteed. A compromised kernel has complete control over the system and can potentially:

- Interfere with eBPF program execution
- Hide events from Tracee
- Manipulate Tracee's data structures
- Disable Tracee entirely

## Two-Tier Adversary Model

Tracee's security guarantees differ significantly depending on whether the adversary operates in userspace or kernel space.

### Userspace Adversaries: Strong Security Boundary

**Target Profile:** Root-privileged adversaries operating in userspace, including containerized environments.

**Tracee's Capabilities:**

Tracee provides strong security boundaries against userspace adversaries through eBPF's architectural guarantees:

**Tamper-Resistant Monitoring**: eBPF programs run in the kernel with their own memory protection. While Tracee's eBPF programs are active and attached:

- Userspace processes cannot bypass the monitoring or evade the attached hooks through normal system operations
- The eBPF bytecode itself cannot be modified once loaded and verified
- Events are captured at the kernel level before userspace can manipulate them
- **However**: Root users with appropriate capabilities (CAP_BPF, CAP_SYS_ADMIN) can administratively disable the monitoring by detaching eBPF programs, killing the Tracee process, or accessing eBPF maps. Tracee's effectiveness assumes the monitoring infrastructure remains intact and that Tracee itself is protected by proper access controls

**Complete Visibility**: Tracee can observe all system calls, LSM hooks, and kernel events from userspace processes, providing comprehensive monitoring of:

- Process execution and lifecycle
- File system operations
- Network activity
- Container escape attempts
- Privilege escalation attempts
- Suspicious behaviors and exploitation techniques

**Security Guarantee:** Userspace adversaries with root privileges cannot evade Tracee's monitoring or bypass its detection mechanisms through userspace operations alone (assuming Tracee itself remains protected and operational).

### Kernel-Level Adversaries: Best-Effort Detection

**Target Profile:** Adversaries with kernel-level access, including rootkits, malicious kernel modules, and kernel zero-day exploits.

**Tracee's Capabilities:**

Against kernel-level adversaries, Tracee provides **best-effort detection** but cannot guarantee protection:

**Rootkits Loaded Before Tracee**: Cannot be reliably detected. If a rootkit compromises the kernel before Tracee starts, it may already have mechanisms to hide from detection or interfere with Tracee's operation.

**Rootkits Loaded After Tracee**: May be detected using known signatures and heuristics. Tracee includes detection capabilities for:

- System call table hooking
- Kernel module loading
- Hidden kernel modules
- Ftrace hooks
- /proc filesystem hooks
- Suspicious kernel modifications

**Kernel Zero-Day Exploits**: Cannot be prevented or reliably detected. An attacker exploiting unknown kernel vulnerabilities can potentially:

- Bypass Tracee's monitoring
- Disable eBPF programs
- Gain complete system control
- Hide their activities from detection

**Limitations:**

- Detection is signature-based and heuristic-driven
- Novel rootkit techniques may evade detection
- Sophisticated kernel-level malware may disable or circumvent Tracee
- Cannot protect against attackers who control the kernel

**Security Guarantee:** Tracee attempts to detect kernel-level threats but cannot guarantee detection or prevention against sophisticated kernel adversaries.

## Security Boundaries and Attack Vectors

### Protected by eBPF Security Model

The following attack vectors are effectively monitored by Tracee due to eBPF's security guarantees:

- **System Calls**: All syscall invocations are observable
- **LSM Hooks**: Linux Security Module hooks provide tamper-resistant checkpoints
- **Network Events**: Packet-level visibility for monitored processes
- **File Operations**: Comprehensive file system activity monitoring
- **Process Lifecycle**: Complete process tree visibility
- **Container Operations**: Container creation, modification, and escape attempts

### Limited or No Protection

The following attack vectors have limited or no protection guarantees:

- **Kernel Memory Manipulation**: Direct kernel memory writes can bypass detection
- **Hardware-Level Attacks**: CPU vulnerabilities, firmware-level compromises
- **Pre-Boot Compromises**: Bootkit, firmware rootkits installed before OS loads
- **Kernel Zero-Days**: Unknown vulnerabilities in the kernel itself
- **eBPF Verifier Bypasses**: Theoretical vulnerabilities in the eBPF verifier (very rare)

## Race Conditions and TOCTOU

### The Problem

When Tracee reads information from user programs, it is subject to a **race condition** where the user program might be able to change the arguments after Tracee reads them. This is known as a Time-of-Check-Time-of-Use (TOCTOU) vulnerability.

Consider this scenario:

A program invokes:

```c
execve("/bin/ls", NULL, 0)
```

Tracee picks this up and reports it. However, the program could change the first argument from `/bin/ls` to `/bin/bash` after Tracee reads it but before the kernel executes it. This means Tracee would report `/bin/ls` while the kernel actually executes `/bin/bash`.

### The Solution: LSM Events

To mitigate this race condition, Tracee provides **LSM (Linux Security Module)** based events. These events occur at security check time within the kernel, providing more reliable data that's harder for user-space programs to manipulate.

#### How to Use LSM Events

For critical security monitoring, you should cross-reference regular syscall events with their corresponding LSM events:

**Example: Process Execution Monitoring**

Instead of relying solely on the `execve` syscall event, also monitor:

- `security_bprm_check` - LSM hook that validates executables before execution

By comparing both events, you can detect potential tampering:

- If the `execve` event shows `/bin/ls`
- But `security_bprm_check` shows `/bin/bash`
- This indicates a TOCTOU attack attempt

#### When to Use LSM Events

Use LSM-based events for:

- **Security-critical monitoring** where argument integrity is essential
- **Detecting evasion techniques** that exploit TOCTOU vulnerabilities
- **Compliance requirements** that demand tamper-resistant auditing

### Best Practices

1. **Defense in Depth**: Use both syscall and LSM events for critical monitoring
2. **Cross-Reference**: Compare data between event types to detect anomalies
3. **Document Assumptions**: If using only syscall events, document the TOCTOU risk
4. **Test Detection**: Verify your policies catch TOCTOU evasion attempts

## Attack Scenarios

### Scenario 1: Container Escape Attempt (Detectable)

**Attack**: An adversary with root privileges inside a container attempts to escape using a known technique (e.g., cgroup release_agent modification).

**Tracee's Response**:

- ✅ Detects the suspicious cgroup modification
- ✅ Triggers `cgroup_release_agent_modification` signature
- ✅ Provides full context: container ID, process tree, file modifications
- ✅ Alerts security teams for immediate response

**Outcome**: Attack detected with full forensic context for response.

### Scenario 2: Rootkit Loaded Before Tracee (Not Detectable)

**Attack**: A kernel rootkit is installed on the system before Tracee starts. The rootkit hooks system calls to hide malicious processes.

**Tracee's Response**:

- ❌ Cannot guarantee detection
- ⚠️ May detect some symptoms if rootkit is imperfect
- ⚠️ Initial system scan may identify some inconsistencies

**Outcome**: Rootkit may remain undetected. **Mitigation**: Deploy Tracee early in the boot process, ideally as part of the init system or container runtime startup.

### Scenario 3: Rootkit Loaded After Tracee (Potentially Detectable)

**Attack**: An adversary attempts to load a kernel module containing a rootkit after Tracee is running.

**Tracee's Response**:

- ✅ Detects kernel module loading event
- ✅ Triggers `kernel_module_loading` signature
- ✅ May detect system call table hooking via `hooked_syscall` event
- ✅ May identify hidden kernel modules via `hidden_kernel_module` event
- ⚠️ Sophisticated rootkits may still evade detection using novel techniques

**Outcome**: Good chance of detection for known techniques, but not guaranteed against advanced adversaries.

### Scenario 4: Privilege Escalation via Exploit (Detectable)

**Attack**: An adversary exploits a userspace vulnerability to escalate privileges (e.g., dirty pipe, container escape via exposed socket).

**Tracee's Response**:

- ✅ Detects suspicious capability usage
- ✅ Identifies unusual process behaviors
- ✅ Monitors credential changes
- ✅ Tracks file and memory modifications

**Outcome**: Attack detected with high confidence.

### Scenario 5: Evading Active Monitoring (Not Possible Without Disabling Tracee)

**Attack**: An adversary with root privileges attempts to evade Tracee's monitoring while performing malicious activities, without administratively disabling Tracee first.

**Tracee's Response**:

- ✅ While eBPF programs are attached and active, userspace operations cannot bypass the monitoring hooks
- ✅ System calls, file operations, network activity, and process events are captured at the kernel level
- ✅ Attempts to manipulate data after capture don't affect what Tracee already observed
- ⚠️ However, an adversary with CAP_BPF or CAP_SYS_ADMIN capabilities can administratively disable Tracee by:
  - Detaching eBPF programs from their hooks
  - Killing the Tracee userspace process
  - Unloading eBPF programs or modifying eBPF maps
- ⚠️ Such administrative actions to disable monitoring may themselves be detectable if other security monitoring is in place

**Outcome**: Evasion of active monitoring is not possible through normal userspace operations. However, an adversary with sufficient capabilities can disable the monitoring infrastructure itself, which is why protecting Tracee's operational integrity is critical.

## Detection Capabilities Overview

| Threat Category | Detection Level | Notes |
|-----------------|----------------|-------|
| Container Escapes | High | Comprehensive monitoring of container boundaries |
| Privilege Escalation | High | Capability and credential monitoring |
| Suspicious Process Behavior | High | Process tree and execution pattern analysis |
| Malicious File Operations | High | Complete file system activity visibility |
| Network Attacks | Medium-High | Packet-level visibility for monitored processes |
| Kernel Module Loading | High | Immediate detection of module loads |
| Rootkits (pre-Tracee) | Low | Cannot reliably detect pre-existing compromises |
| Rootkits (post-Tracee) | Medium | Signature-based detection of known techniques |
| Kernel Zero-Days | Low | Cannot detect unknown kernel vulnerabilities |
| Hardware Attacks | None | Outside Tracee's scope |

## Mitigation Strategies

### Maximize Protection

1. **Deploy Early**: Start Tracee as early as possible in the boot sequence to establish trust before potential compromises
2. **Use LSM Events**: Prefer LSM-based events for security-critical monitoring to avoid TOCTOU vulnerabilities
3. **Enable All Rootkit Signatures**: Activate all kernel integrity monitoring signatures (hooked_syscall, hidden_kernel_module, etc.)
4. **Layered Security**: Combine Tracee with other security controls:
   - Secure boot to verify kernel integrity
   - Kernel module signing to prevent unauthorized module loads
   - SELinux/AppArmor for mandatory access control
   - Network segmentation
   - Regular vulnerability scanning

### Acknowledge Limitations

1. **Understand Boundaries**: Be aware that kernel-level compromises can bypass Tracee
2. **Verify Kernel Integrity**: Use external tools to verify kernel integrity before trusting Tracee's output
3. **Monitor Tracee Itself**: Watch for signs that Tracee may have been tampered with (e.g., unexpected crashes, missing events)
4. **Regular Updates**: Keep Tracee, the kernel, and eBPF subsystem updated to benefit from latest security fixes
5. **Incident Response Plan**: Have procedures for handling scenarios where Tracee's integrity may be compromised

### Operational Best Practices

1. **Start with Known-Good State**: Deploy Tracee on freshly provisioned or verified clean systems
2. **Baseline Normal Behavior**: Establish baselines before deploying to production
3. **Alert Tuning**: Configure appropriate alert thresholds to balance detection and false positives
4. **Regular Review**: Periodically review detected events and tune signatures
5. **Forensic Capabilities**: Enable artifact capture for post-incident analysis

## Related Documentation

- [Capabilities](install/capabilities.md) - Learn about running Tracee with least privileges
- [Rootkit Detection Events](events/builtin/security-events.md) - Detailed documentation on kernel integrity monitoring
- [Policies](policies/index.md) - Create policies that implement defense-in-depth
- [Forensics](forensics.md) - Capture artifacts for investigation

## Summary

Tracee provides **strong security guarantees against userspace adversaries** through eBPF's tamper-resistant architecture. However, it offers only **best-effort detection against kernel-level adversaries** and cannot protect against attackers who control the kernel before Tracee starts or exploit kernel zero-day vulnerabilities.

By understanding these boundaries and implementing layered security controls, you can maximize Tracee's effectiveness as part of a comprehensive security strategy.


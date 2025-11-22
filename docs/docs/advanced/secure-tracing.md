# Secure Tracing and Race Conditions

## Overview

When Tracee reads information from user programs, it is subject to a **race condition** where the user program might be able to change the arguments after Tracee reads them. This is known as a Time-of-Check-Time-of-Use (TOCTOU) vulnerability.

## The Problem

Consider this scenario:

A program invokes:

```c
execve("/bin/ls", NULL, 0)
```

Tracee picks this up and reports it. However, the program could change the first argument from `/bin/ls` to `/bin/bash` after Tracee reads it but before the kernel executes it. This means Tracee would report `/bin/ls` while the kernel actually executes `/bin/bash`.

## The Solution: LSM Events

To mitigate this race condition, Tracee provides **LSM (Linux Security Module)** based events. These events occur at security check time within the kernel, providing more reliable data that's harder for user-space programs to manipulate.

### How to Use LSM Events

For critical security monitoring, you should cross-reference regular syscall events with their corresponding LSM events:

**Example: Process Execution Monitoring**

Instead of relying solely on the `execve` syscall event, also monitor:
- `security_bprm_check` - LSM hook that validates executables before execution

By comparing both events, you can detect potential tampering:
- If the `execve` event shows `/bin/ls`
- But `security_bprm_check` shows `/bin/bash`
- This indicates a TOCTOU attack attempt

### When to Use LSM Events

Use LSM-based events for:
- **Security-critical monitoring** where argument integrity is essential
- **Detecting evasion techniques** that exploit TOCTOU vulnerabilities
- **Compliance requirements** that demand tamper-resistant auditing

## Best Practices

1. **Defense in Depth**: Use both syscall and LSM events for critical monitoring
2. **Cross-Reference**: Compare data between event types to detect anomalies
3. **Document Assumptions**: If using only syscall events, document the TOCTOU risk
4. **Test Detection**: Verify your policies catch TOCTOU evasion attempts

## Related Documentation

- [Events Documentation](../events/index.md) - Learn about available LSM events
- [Policies](../policies/index.md) - Create policies that use multiple event types


# LSM BPF Support

Linux Security Module (LSM) BPF allows eBPF programs to attach to security hooks for **enforcing security policies**. Unlike tracing, LSM programs can **allow or deny** security-sensitive operations like file access, process execution, and network connections. Most systems don't support this feature.

## Quick Check

Check if your system supports LSM BPF:

```bash
# Build the LSM check tool
make lsm_check

# Check LSM support (requires root)
sudo ./dist/lsm_check

# Quiet mode (exit code only)  
sudo ./dist/lsm_check --quiet
```

**Exit codes:**
- `0`: Supported ✅
- `1`: Not supported (normal) ⚠️  
- `2`: Error (insufficient privileges or other issues) ❌

## Requirements

### Kernel Version
- **x86_64**: Linux 5.7+ 
- **ARM64**: Linux 6.4+ (critical - earlier versions don't work)

### Configuration
Your kernel needs:
```bash
CONFIG_BPF_LSM=y               # BPF LSM support
CONFIG_LSM="...,bpf"           # Include bpf in LSM list
```

Although `CONFIG_BPF_LSM` is often enabled in many popular distributions, the `CONFIG_LSM` setting may not include "bpf" in its list, which means BPF LSM support could still be unavailable.

**ARM64 specific requirement:**
For ARM64 systems, you can check if LSM BPF support is possible by verifying:
```bash
CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS=y
```

This configuration option indicates whether the kernel has the ftrace direct call infrastructure required for ARM64 LSM BPF. If this option is not enabled or not available, LSM BPF will not work regardless of other settings (attachment of LSM programs will result `ENOTSUP` error).

### Boot Parameters

LSM modules are enabled through kernel boot parameters, which **override** the compile-time `CONFIG_LSM` setting. The `lsm=` parameter specifies which security modules to load at boot time.

**Important**: Boot parameters take precedence over `CONFIG_LSM`. If no `lsm=` parameter is specified, the kernel uses the compiled-in `CONFIG_LSM` default.

Verify current LSM configuration:
```bash
cat /sys/kernel/security/lsm
```

## Platform-Specific Notes

### ARM64 Support Issues

**Important**: ARM64 LSM BPF was broken for 3 years (Linux 5.7-6.3) due to missing kernel infrastructure.

**Fix commits:**
- **BPF Trampoline**: `efc9909fdce0` - "bpf, arm64: Add bpf trampoline for arm64" (by Xu Kuohai, Huawei)
- **Ftrace Direct Calls**: "Add ftrace direct call for arm64" patch series (by Florent Revest, Google) - merged in Linux 6.4

For detailed technical analysis of the ARM64 limitations and the underlying ftrace infrastructure issues, see: [Exploring BPF LSM support on aarch64 with ftrace](https://www.exein.io/blog/exploring-bpf-lsm-support-on-aarch64-with-ftrace)

### x86_64 Support
Kernel support works reliably on all modern distributions with kernel 5.7+. However, **BPF LSM is rarely enabled** in standard configurations.

## Why It Might Not Work

**Common reasons LSM BPF fails:**

1. **Kernel too old** (especially ARM64 < 6.4, but also < 5.7 in x86)
2. **CONFIG_BPF_LSM not enabled** in kernel
3. **The bpf LSM module is not supported** (i.e., `bpf` is missing from the `lsm=` boot parameter and/or from the `CONFIG_LSM` kernel configuration)

## Bottom Line

LSM BPF is a **security policy enforcement** feature that allows custom security rules. Tracee works fine without it. 

**Most systems support LSM infrastructure but BPF LSM is rarely enabled in standard configurations** - this is normal and expected.
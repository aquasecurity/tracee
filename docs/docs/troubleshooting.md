# Troubleshooting

This guide helps you diagnose and resolve common issues when running Tracee.

## Installation Issues

### BTF Not Available

**Problem**: Error message about missing BTF support
```
ERRO error loading eBPF program: BTF is required
```

**Solution**: 

1. Check if BTF is available: `ls /sys/kernel/btf/vmlinux`
2. If missing, upgrade to a kernel version that includes BTF support (most modern distributions)
3. See [Prerequisites](install/prerequisites.md#btf) for more details

### Permission Denied

**Problem**: Tracee fails to start with permission errors
```
ERRO permission denied loading eBPF program
```

**Solutions**:

1. **Run as root**: `sudo tracee`
2. **Use required capabilities**:
   ```bash
   # Docker - minimal required capabilities
   docker run \
     --cap-add SYS_RESOURCE \
     --cap-add SYS_ADMIN \
     --cap-add SYS_PTRACE \
     --cap-add NET_ADMIN \
     --cap-add SYSLOG \
     tracee
   
   # Kubernetes
   securityContext:
     capabilities:
       add: 
         - "SYS_RESOURCE"
         - "SYS_ADMIN" 
         - "SYS_PTRACE"
         - "NET_ADMIN"
         - "SYSLOG"
   ```
3. **For recent kernels (>=5.8)**, you may use `CAP_BPF` + `CAP_PERFMON` instead of `CAP_SYS_ADMIN`
4. See [Prerequisites](install/prerequisites.md#process-capabilities) for complete details and justifications

### Kernel Version Incompatibility

**Problem**: Unsupported kernel version errors

**Solution**: 

- Check supported kernels: [Prerequisites](install/prerequisites.md#kernel-version)
- Tracee requires kernel 5.4 or newer (4.18 for RHEL 8)
- Consider upgrading to a supported kernel version

## Runtime Issues

### No Events Generated

**Problem**: Tracee starts but produces no events

**Troubleshooting steps**:

1. **Check scope filters**:
   ```bash
   # Test with minimal configuration
   tracee --events execve
   ```

2. **Verify events are enabled**:
   ```bash
   # List enabled events
   tracee --events help
   ```

3. **Check policy configuration**:
   ```yaml
   # Ensure policy scope matches your workload
   scope:
     - container  # Or specific process filters if needed
   ```

### High CPU Usage

**Problem**: Tracee consuming excessive CPU

**Solutions**:

1. **Reduce event scope**:
   ```yaml
   scope:
     - container  # Limit to containers only
   ```

2. **Filter events**:
   ```yaml
   rules:
     - event: execve
       filters:
         - uid!=0  # Example: exclude root processes
   ```

3. **Use specific events instead of sets**:
   ```yaml
   rules:
     - event: execve        # Specific event
     # - event: tag=syscalls    # Avoid broad tags
   ```

## Container Issues

### Container Events Not Captured

**Problem**: Missing container-related events

**Solutions**:

1. **Mount container runtime socket**:
   ```bash
   # Docker
   docker run -v /var/run/docker.sock:/var/run/docker.sock tracee
   
   # Containerd
   docker run -v /run/containerd/containerd.sock:/run/containerd/containerd.sock tracee
   ```

## Performance Issues

### Events Being Dropped

**Problem**: Warning about dropped events
```
WARN events dropped due to buffer overflow
```

**Solutions**:

1. **Increase buffer size**:
   ```bash
   tracee --buffers kernel-events=1024
   ```

2. **Reduce event frequency**:
   ```yaml
   rules:
     - event: openat
       filters:
         - data.pathname!=/tmp/*  # Filter noisy paths
   ```

### Slow Event Processing

**Problem**: Events arrive with significant delay

**Solutions**:

1. **Check system load**: Use `top`, `htop` to verify system isn't overloaded
2. **Optimize event selection**: Use specific events instead of broad event sets

## Output Issues

### JSON Parsing Errors

**Problem**: Invalid JSON output

**Solutions**:

1. **Use proper output format**:
   ```bash
   tracee --output json --enrichment decoded-data
   ```

2. **Check for mixed output**:
   ```bash
   # Separate logs from events
   tracee --output json --logging file=/var/log/tracee.log
   ```

### Missing Event Fields

**Problem**: Expected fields not present in events

**Solutions**:

1. **Enable argument parsing**:
   ```bash
   tracee --enrichment decoded-data
   ```

2. **Check event definition**: Some events may not include all expected fields

## Debugging

### Enable Debug Logging

```bash
# Enable debug logs
tracee --logging level=debug

# Or via environment
TRACEE_LOG_LEVEL=debug tracee
```

### Capture System Information

```bash
# System info for bug reports
tracee --version
uname -a
cat /etc/os-release
ls -la /sys/kernel/btf/vmlinux
```

### Test Minimal Configuration

```bash
# Minimal test configuration
sudo tracee --events execve
```

## Getting Help

If you continue experiencing issues:

1. **Search existing issues**: [GitHub Issues](https://github.com/aquasecurity/tracee/issues)
2. **Check discussions**: [GitHub Discussions](https://github.com/aquasecurity/tracee/discussions)
3. **Join Slack**: [Aqua Community Slack](https://slack.aquasec.com)

When reporting issues, include:

- Tracee version (`tracee --version`)
- Operating system and kernel version
- Container runtime (if applicable)
- Complete error messages
- Minimal reproduction steps

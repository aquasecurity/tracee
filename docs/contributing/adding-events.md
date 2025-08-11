# Adding New Events

This guide walks you through the process of adding new event monitoring capabilities to Tracee. Adding new events involves modifications to several files across the codebase.

## Overview

Adding a new event to Tracee requires changes in four main areas:

1. **eBPF Implementation** - Implement the actual event handling logic
2. **Probe Configuration** - Configure how the event attaches to kernel functions
3. **Event Definition** - Define the event and its metadata in Go code
4. **Event Documentation** - Create documentation file for the event

## Step-by-Step Process

### 1. Implement eBPF Program in `pkg/ebpf/c/tracee.bpf.c`

**Choose a kernel function to monitor:**
- **System calls**: `sys_openat`, `sys_execve`
- **LSM hooks**: `security_file_open`, `security_bprm_check`
- **VFS operations**: `vfs_read`, `vfs_write`
- **Network**: `tcp_connect`, `inet_csk_accept`

**Find functions:** `cat /proc/kallsyms | grep function_name`

**Implement the eBPF program:**

```c
SEC("kprobe/your_kernel_function")          // Must match probe configuration
int BPF_KPROBE(trace_your_event)            // This name will be used in probe config
{
    // Your event implementation follows this pattern:
    // 1. Initialize program data
    // 2. Apply scope filtering
    // 3. Extract data fields
    // 4. Apply data field-based filtering
    // 5. Submit event

    program_data_t p = {};
    if (!init_program_data(&p, ctx, YOUR_EVENT_ID))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    // Extract data fields from kernel function
    void *arg1 = (void *)PT_REGS_PARM1(ctx);
    int arg2 = PT_REGS_PARM2(ctx);

    // Apply data field-based filtering if needed
    // ... your filtering logic ...

    // Save data fields to event buffer
    save_str_to_buf(&p.event->args_buf, arg1, 0);
    save_to_submit_buf(&p.event->args_buf, &arg2, sizeof(arg2), 1);

    events_perf_submit(&p, 0);
    return 0;
}
```

### 2. Configure Probes in `pkg/ebpf/probes/probe_group.go`

Add the probe configuration that matches your eBPF function names:

```go
// In pkg/ebpf/probes/probe_group.go, add to allProbes map in NewDefaultProbeGroup():
YourNewEvent: NewTraceProbe(KProbe, "your_kernel_function", "trace_your_event"),
```

**Attachment types:**
- `KProbe` - Attaches to kernel function entry (most common)
- `KretProbe` - Attaches to kernel function exit (for return values)
- `Tracepoint` - Attaches to predefined kernel tracepoints (stable interface)
- `SyscallEnter`/`SyscallExit` - Specialized for system call entry/exit

### 3. Define the Event in `pkg/events/core.go`

**Choose an event ID** from the appropriate range and add it to both eBPF and Go code:

**Event ID Ranges:**
- Common events: 1-699 (most events)
- Network events: 700-1999
- User-space network: 2000-3999
- Capture meta-events: 4000-4999
- Signal meta-events: 5000+

**In eBPF (`pkg/ebpf/c/tracee.bpf.c`):**
```c
#define YOUR_EVENT_ID 42
```

**In Go (`pkg/events/core.go`):**
{% raw %}
```go
// Add to appropriate const block (around line 100-200):
YourNewEvent = 42    // Must match eBPF ID

// Add to Core variable (around line 500+):
YourNewEvent: {
    id:      YourNewEvent,
    id32Bit: Sys32Undefined,
    name:    "your_event_name",
    version: NewVersion(1, 0, 0),
    sets:    []string{"fs"}, // Choose: syscalls, fs, net, security, proc, default
    fields: []DataField{
        {DecodeAs: data.STR_T, ArgMeta: trace.ArgMeta{Type: "const char*", Name: "pathname"}},
        {DecodeAs: data.INT_T, ArgMeta: trace.ArgMeta{Type: "int", Name: "flags"}},
        // Add all event data fields
    },
    dependencies: Dependencies{
        probes: []Probe{{handle: probes.YourNewEvent, required: true}},
    },
},
```
{% endraw %}

## Testing Your New Event

### 4. Build and Test Compilation

```bash
# Build Tracee with your changes
make tracee

# Verify no compilation errors
echo $?  # Should be 0
```

### 5. Test Event Functionality

```bash
# Test that your event can be selected
sudo ./dist/tracee --events your_event_name --output json

# Test with policies
sudo ./dist/tracee --config-file your_test_policy.yaml
```

### 6. Unit Tests

Add unit tests for your event definition and run them:

```bash
# Run unit tests
make test-unit

# Run integration tests
make test-integration
```

```go
// In appropriate _test.go file
func TestYourNewEvent(t *testing.T) {
    // Test event definition
    // Test data field extraction
    // Test filtering behavior
}
```

### 7. Integration Tests

Consider adding integration tests that actually trigger your event and verify it's captured correctly.

### 8. Create Event Documentation

After everything is working, create a markdown file in the `docs/` directory to document your event.

**Required Documentation Sections:**

- **Description**: Explain what the event captures, when it triggers, and its purpose
- **Event Sets**: Document which event sets this event belongs to (e.g., syscalls, fs, net)
- **Data Fields**: List and describe all data fields returned by the event
- **Dependencies**: Document kernel probes and any other requirements
- **Use Cases**: Provide practical examples of when and why to use this event

**Documentation Guidelines:**
- Follow the existing format used by other event documentation files
- Provide clear descriptions of all data fields with their types
- Explain the security or operational significance
- Include practical use cases and examples
- Cross-reference related events when appropriate

## Common Patterns

- **System calls**: Hook `sys_*` functions, use `SyscallEnter`/`SyscallExit` probes
- **Security events**: Hook `security_*` functions, use `KProbe` attachments
- **File operations**: Hook VFS functions (e.g., `vfs_read`, `vfs_write`)
- **Network events**: Hook network functions, extract connection info

## Best Practices

- **Keep eBPF programs lightweight** - apply filtering early, minimize processing
- **Use descriptive names** - follow existing naming conventions
- **Document data fields clearly** - explain purpose and format of each field
- **Choose appropriate event sets** - helps users discover and select your event
- **Test thoroughly** - verify event triggers correctly and data is accurate

## Troubleshooting

### Common Issues

**Compilation Errors:**
- Verify event IDs don't conflict
- Check eBPF program section names match probe configuration
- Ensure all required headers are included

**Runtime Issues:**
- Check kernel compatibility for attachment points
- Verify probe symbols exist on target kernel
- Test with `bpftrace` first for complex kernel function monitoring

**Event Not Triggering:**
- Verify the kernel function is actually called for your test case
- Check filtering logic in eBPF program
- Use `bpf_printk()` for debugging eBPF code

### Debugging Tools

```bash
# Check eBPF program loading
bpftool prog list

# Monitor eBPF logs
cat /sys/kernel/debug/tracing/trace_pipe

# Test kernel symbol availability
cat /proc/kallsyms | grep your_symbol
```

## Getting Help

- **GitHub Issues**: Ask questions about event implementation
- **Discussions**: Discuss design decisions for complex events
- **Code Review**: Submit WIP PRs for feedback on approach

## Related Resources

- [eBPF Programming Guide](https://ebpf.io/)
- [Linux Tracepoints](https://www.kernel.org/doc/html/latest/trace/tracepoints.html)
- [BPF LSM Documentation](https://www.kernel.org/doc/html/latest/bpf/prog_lsm.html)
- [Tracee Documentation](../docs/overview.md)

# Output Options

Tracee supports different output options for enriching events with additional context and information.

!!! Note
    These options will be migrated to the `--enrichment` flag in a future release.

## Available Options

### stack-addresses

Include stack memory addresses in events for debugging and analysis.

**Configuration:**
```yaml
output:
  options:
    stack-addresses: true
```

**CLI:**
```bash
tracee --output option:stack-addresses
```

### parse-arguments

Parse event arguments into human-readable format instead of raw values. Recommended for interactive use and readability, but may add processing overhead that impacts performance on high-volume event streams.

**Configuration:**
```yaml
output:
  options:
    parse-arguments: true
```

**CLI:**
```bash
tracee --output option:parse-arguments
```

### exec-env

Include execution environment variables in process execution events (particularly useful for `execve` events).

**Configuration:**
```yaml
output:
  options:
    exec-env: true
```

**CLI:**
```bash
tracee --output option:exec-env
```

### exec-hash

Include file SHA256 hashes and process creation time (ctime) in `sched_process_exec` events. Useful for comparing executed binaries against known hash lists.

The option controls the hash caching strategy for performance and correctness tradeoffs.

**Configuration:**
```yaml
output:
  options:
    exec-hash: dev-inode
```

**CLI:**
```bash
tracee --output option:exec-hash=dev-inode
```

**Available modes:**

- `inode` - Recalculate hash if inode's ctime differs (performant, may miss changes)
- `dev-inode` - Key by device+inode pair (recommended: good balance of performance and correctness)
- `digest-inode` - Key by container image digest+inode (most efficient, requires container enrichment)

!!! Note
    All modes calculate SHA256 hashes. The mode only affects the caching strategy used to avoid recalculating hashes for the same binary.

### parse-arguments-fds

Parse file descriptor arguments to show associated file paths instead of just the descriptor number.

**Configuration:**
```yaml
output:
  options:
    parse-arguments-fds: true
```

**CLI:**
```bash
tracee --output option:parse-arguments-fds
```

### sort-events

Enable chronological sorting of events. On busy systems, events may be received out of order. This option ensures events are output in the order they occurred.

See the [Sorting Events](./sorting-events.md) documentation for details on how this works.

**Configuration:**
```yaml
output:
  options:
    sort-events: true
```

**CLI:**
```bash
tracee --output option:sort-events
```

## See Also

- [Output Flag Reference](../flags/output.1.md) - Complete output configuration
- [Output Overview](./index.md) - Output system overview
- [Sorting Events](./sorting-events.md) - Event ordering details
- [Enrichment Flag Reference](../flags/enrichment.1.md) - Container and process enrichment

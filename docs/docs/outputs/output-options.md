# Output Options

Tracee supports different output options for enriching events with additional context and information.

## Available Options

### sort-events

Enable chronological sorting of events. On busy systems, events may be received out of order. This option ensures events are output in the order they occurred.

See the [Sorting Events](./sorting-events.md) documentation for details on how this works.

**Configuration:**
```yaml
output:
  sort-events: true
```

**CLI:**
```bash
tracee --output sort-events
```

## See Also

- [Output Flag Reference](../flags/output.1.md) - Complete output configuration
- [Output Overview](./index.md) - Output system overview
- [Sorting Events](./sorting-events.md) - Event ordering details
- [Enrichment Flag Reference](../flags/enrichment.1.md) - Container and process enrichment

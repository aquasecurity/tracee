# Streams

Streams are a Tracee mechanism that let you redirect events to different destinations with custom filters. Streams can only be configured through the configuration file.

Using streams allows you to build complex event-routing pipelines, applying filters based on events and policies. Stream configuration is straightforward:

```yaml
output:
    destinations:
    - name: json_destination
      format: json

    streams:
    - name: tracing
      destinations: ["json_destination"]
      filters:
        events: []
        policies: []
      buffer:
        mode: block # or drop
        size: 1024
```

A stream must always reference one or more destinations.  
When a stream contains multiple destinations, every event emitted by the stream is broadcast to **all** destinations.  
Be aware that if one destination is slow, it may delay all others.

**Important:** A stream can be use multiple destinations, but a destination cannot be reused in multiple streams.

Streams are first-class citizens in Tracee. If you [declare a destination](./output-formats.md) without explicitly creating a stream, Tracee automatically creates an implicit filter-less stream to emit events to that destination.

!!! Tip
    A common pattern is to use streams to send different verbosity levels or event types to different destinations.

## Example

```yaml
output:
    destinations:
    - name: json_destination
      format: json
    
    - name: webhook_destination
      format: json
      url: http://localhost:8080/processes?timeout=5s
    
    - name: fluent_destination
      format: json
      url: http://localhost:2222?tag=severe

    streams:
    - name: tracing
      destinations: 
        - json_destination

    - name: processes
      destinations: 
        - webhook_destination
      filters:
        events:
          - sched_process_exec
          - sched_process_fork
          - sched_process_exit
      buffer:
        mode: drop
    
    - name: severe_events
      destinations:
        - fluent_destination
      filters:
        policies:
          - severe-events-policy
      buffer:
        mode: drop # using drop to avoid losing events
```

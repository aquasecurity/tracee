---
title: TRACEE-INFO
section: 1
header: Tracee Event Manual
---

## NAME

**tracee_info** - export Tracee metadata and runtime information

## DESCRIPTION

This event is emitted during Tracee's initialization and is typically the first event generated. It provides essential metadata about Tracee's configuration and runtime environment, which is valuable for event processing, troubleshooting, and understanding the context of captured events.

The event is particularly useful when working with Tracee's File Source feature, as it provides information about how Tracee was configured during the original capture.

This event is useful for:

- **Timing analysis**: Calculate relative event timings
- **Version tracking**: Identify Tracee version for compatibility
- **Troubleshooting**: Understand runtime environment
- **Event processing**: Provide context for other events

## EVENT SETS

**none**

## DATA FIELDS

**boot_time** (*uint64*)
: The system boot time relative to the Unix epoch

**start_time** (*time.Time*)
: The time when the Tracee process started, relative to system boot time

**version** (*string*)
: The version of Tracee that generated the events

## DEPENDENCIES

This event has no dependencies as it is generated directly by Tracee during initialization.

## USE CASES

- **Event timing**: Calculate relative timestamps for other events

- **Compatibility checking**: Verify event stream compatibility with tools

- **Troubleshooting**: Identify environment-specific issues

- **Audit logging**: Record Tracee version and runtime context

## IMPLEMENTATION NOTES

- Generated in user-mode during initialization
- Always the first event in an event stream
- Provides foundational context for event processing
- No kernel probes or special permissions required

## EXAMPLES

The event can be used to calculate relative event timing:
```
relative_time = event.timestamp - (tracee_info.boot_time + tracee_info.start_time)
```

## RELATED EVENTS

- **init_namespaces**: Namespace initialization information
- **process_execute**: Tracee process execution details
- **process_init**: Process initialization events

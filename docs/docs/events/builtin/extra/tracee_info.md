# tracee_info

## Intro

tracee_info - An event that exports some relevant data of Tracee upon startup.

## Description

This event, created in user-mode during Tracee's initialization, is typically the first event emitted. It provides valuable metadata about Tracee's configuration and runtime environment, which can be helpful for event processing and troubleshooting.

The event was created also with Tracee's File Source in mind, to provide information about how Tracee ran during the original capture.

## Arguments

* `boot_time`:`u64`[U] - the boot time of the system that Tracee is running on, relative to the Unix epoch.
* `start_time`:`u64`[U] - the time the Tracee process started relative to system boot time.
* `version`:`const char*`[U] - Tracee version.

## Hooks

## Example Use Case

The event could be used to calculate the relative time of events since Tracee's start.

## Related Events

`init_namespaces`
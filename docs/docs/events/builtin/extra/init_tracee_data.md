# init_tracee_data

## Intro

init_tracee_data - An event that exports some relevant data of Tracee upon startup.

## Description

This is an event create in user-mode upon Tracee's initialization. Hence, it should be one of the first events to be created by Tracee.
The event is used to pass the user some internal data of Tracee that might have some significant for events analyze.
The event was created also with the Analyze mode of Tracee in mind, to pass the Analyze mode some information regarding how Tracee ran during runtime.

## Arguments

* `boot_time`:`u64`[U] - the boot time of the system Tracee run in since epoch.
* `start_time`:`u64`[U] - the time Tracee started since epoch.

## Hooks

## Example Use Case

The event could be used to calculate the relative time of events since Tracee's start.

## Related Events

`init_namespaces`
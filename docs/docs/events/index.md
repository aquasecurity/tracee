# Events

Events refer to the activity in a system that tracee monitors. There are two main types of events, built-in events that are part of Tracee and custom events, which references the way users define other events that Tracee should monitor. 

As part of built-in events, there are six types of events:

* syscalls 
* network 
* security 
* lsm 
* containers 
* misc

This section documents all of the different events that Tracee exposes.

## Defining events

Tracing the `execve` events in a [policy](../policies/index.md):

```
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
	name: sample-policy
	annotations:
		description: traces execve events
spec:
	scope:
	  - global
	rules:
	  - event: execve
```

If no event is passed with [filters] or [policies], tracee will start with a set of default events.

Please head over to the [Tracee usage](../usage/index.md) documentation for more information on configuring events.

### Event Sets QUESTION

Events can be part of a set. For example, `default`, `network_events`, `syscalls`. 
We can ask Tracee to trace a full set, or sets, instead of passing event by event, for example:

```
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
	name: sample-policy
	annotations:
		description: traces execve events
spec:
	scope:
	  - global
	rules:
	  - event: syscalls
```

## Read in AVD

[Aqua Vulnerability Database (AVD)](https://avd.aquasec.com) is a public index of all security information that can be reported across all of Aqua's products and tools. As such, it also contains entries about Tracee security events. The AVD entries on runtime security are generated from the [detection signatures](https://github.com/aquasecurity/tracee/tree/main/signatures) and are organized by MITRE ATT&CK categorization. Browse at [avd.aquasec.com/tracee](https://avd.aquasec.com/tracee/).

👈 Please use the side-navigation on the left in order to browse the different topics.

[filters]: ../../filters/filtering
[policies]: ../../policies

## Video Content

If you are curious to learn more about the Tracee Events architecture and related decision making, then have a look at the following video Q&A:

Everything is an Event in Tracee 
  [![Watch the video](../../images/liveqa.png)](https://www.youtube.com/live/keqVe4d71uk?si=OTbVxgWsFBtdqEMW)

# Events

Events refer to the system activity that tracee monitors. There are two types of events, built-in events that are part of Tracee and custom events, which are user defined events. 

As part of built-in events, there are six types of events:

* syscalls 
* network 
* security 
* lsm 
* containers 
* misc

This section documents all of the different events that Tracee exposes.

## Configuring Tracee Events

Events are defined in the [Policy](../policies/index.md) YAML manifest. 

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

Please head over to the [Tracee usage](../policies/usage/kubernetes.md) documentation for more information on configuring events.

### Event Sets

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

## Video Content

If you are curious to learn more about the Tracee Events architecture and related decision making, then have a look at the following video Q&A:

Everything is an Event in Tracee 
  [![Watch the video](../../images/liveqa.png)](https://www.youtube.com/live/keqVe4d71uk?si=OTbVxgWsFBtdqEMW)

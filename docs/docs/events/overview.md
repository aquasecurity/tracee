# Events

This section documents all of the different events that Tracee exposes.

## Everything is an event

Tracee uses eBPF technology to tap into your system and give you access to hundreds of events that help you understand how your system behaves. The events can be specified either through CLI with [filters] or with [policies].

### Using the CLI

Tracing `execve` events with [filters]:

```console
tracee --events execve
```

### Through the Tracee Helm Chart installation

Tracing `execve` events with [policies]:

```
cat <<EOF >sample_policy.yaml
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
EOF
```

```
tracee --policies sample_policy.yaml
```

If no event is passed with [filters] or [policies], tracee will start with a set of default events.
Below a list of tracee default events.

### Sets

Events can be part of a set, for example on the table above we can see a few sets like `default`, `network_events`, `syscalls`. 
We can ask tracee to trace a full set, or sets, instead of passing event by event, for example:

```console
tracee --events syscalls
```
or 

```console
tracee --events syscalls,network_events
```


## Read in CLI

You can view the list of available events and their schema by running `tracee list` command.

## Read in AVD

[Aqua Vulnerability Database (AVD)](https://avd.aquasec.com) is a public index of all security information that can be reported across all of Aqua's products and tools. As such, it also contains entries about Tracee security events. The AVD entries on runtime security are generated from the [detection signatures](https://github.com/aquasecurity/tracee/tree/main/signatures) and are organized by MITRE ATT&CK categorization. Browse at [avd.aquasec.com/tracee](https://avd.aquasec.com/tracee/).

👈 Please use the side-navigation on the left in order to browse the different topics.

[filters]: ../../filters/filtering
[policies]: ../../policies

## Video Content

If you are curious to learn more about the Tracee Events architecture and related decision making, then have a look at the following video Q&A:

Everything is an Event in Tracee 
  [![Watch the video](../../images/liveqa.png)](https://www.youtube.com/live/keqVe4d71uk?si=OTbVxgWsFBtdqEMW)

# CLI Usage

This section details how to use the flags in the Tracee CLI.

## Applying Tracee Polcies

A [policy file](../policies/index.md) can be applied in the Tracee command using the `--policy` flag and providing a path to the location of the policy file.

```console
tracee --policy ./policy.yml
```

## Tracee Events

As an alternative to using Tracee policies, specific Events can be applied to the Tracee command through the `--events` flag:
```console
tracee --events <name of the event>
```

For example:
```console
tracee --events fsopen
```

You can view the list of available events and their schema by running `tracee list` command.

### Event Sets

Events can be part of a set. For example, `default`, `network_events`, `syscalls`. 
We can ask Tracee to trace a full set, or sets, instead of passing event by event, for example:

```console
tracee --events syscalls
```
or 

```console
tracee --events syscalls,network_events
```

Tracing `execve` events with [filters]:

```console
tracee --events execve
```

## Analyze

The tracee subcommand `analyze` allows you to execute security signatures on past data. 
For example, you can collect the ptrace event into one node using the following command:

```
tracee --events=ptrace --output=json:events.json
```

Then, on another node, you can check if the behavior signature for anti-debugging was triggered using the following command:

```
tracee analyze --events=anti_debugging events.json
```

The `analyze` command can also be used to test new signatures from the collected past data. You can run tracee on a node, collect several events, and based on the collected events, create your behavior signature. Afterward, you can test if the signature would be triggered using the `analyze` command.

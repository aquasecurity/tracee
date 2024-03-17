# Analyze

The tracee subcommand `analyze` allows you to execute behavior signatures on past data.
For it to work properly, the `analyze_essentials` events set should be selected when tracing.
For example, you can collect the ptrace event into one node using the following command:

```
tracee --events ptrace --output json:events.json -e analyze_essentials
```

Then, on another node, you can check if the behavior signature for anti-debugging was triggered using the following command:

```
tracee analyze --events anti_debugging --input json:events.json
```

The `analyze` command can also be used to test new signatures from the collected past data. You can run tracee on a node, collect several events, and based on the collected events, create your behavior signature. Afterward, you can test if the signature would be triggered using the `analyze` command.

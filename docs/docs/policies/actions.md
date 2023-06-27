# Actions

## DefaultActions

Every policy must have at least one action in `defaultActions`. Actions are taken when there is match on some rule declared at the policy. The following actions are currently supported:

- `log` - output events in a specified foramt (table, json etc) - default is table. The path to file is stdout.
- `forward` - send events in json format using the Forward protocol to a Fluent receiver
- `webhook` - send events in json format to the webhook url

### Log action:

By default the log action will output table to stdout, but it can be configured with the [`--output`](../../outputs/output-formats) flag. For example we have a policy log `dropped_executable` events:

```yaml
name: log_sample_policy
description: log sample policy
scope:
  - global
defaultActions: 
  - log
rules:
  - event: dropped_executable
```

if we start tracee it will log table to stdout:

```console
tracee --policy policy.yaml
```

To customize it, we use the [`--output`](../../outputs/output-formats) flag, for example, instead of table we would like to log a json to stdout:

```console
tracee --policy policy.yaml --output json
```

Or to send json logs to a file:

```console
tracee --policy policy.yaml --output json:/path/to/file
```

In order to use the other actions, we are obligated to declare their outputs before:

### Webook action:

```yaml
name: webhook_sample_policy
description: webhook_sample_policy
scope:
  - global
defaultActions: 
  - webhook
rules:
  - event: dropped_executable
```

```console
tracee --policy policy.yaml --output webhook:http://localhost:8080
```

### Forward action:

For the forward action:

```yaml
name: forward_sample_policy
description: forward_sample_policy
scope:
  - global
defaultActions: 
  - forward
rules:
  - event: dropped_executable
```

```console
tracee --policy policy.yaml --output forward:tcp://localhost:24224
```

## Multiple outputs

Tracee supports multiple outputs, and when used with policies, we have a broadcast by type.
For example, if you declared an output to json stdout and an output table to a file, the log action
will broadcast the event matched to both outputs.

```yaml
name: log_sample_policy
description: log sample policy
scope:
  - global
defaultActions: 
  - log
rules:
  - event: dropped_executable
```

```console
tracee --policy policy.yaml --output json:stdout --output table:/path/to/file
```

!!! Tip
    Although we have shown examples of configuring outputs with the flag [`--output`](../../outputs/output-formats), the same can be done with tracee's [config file](../../config/overview).

## Rule Actions

A Rule can override default action of a policy. For example, if you create a policy which by default will log, we can change a rule to send a webhook if a match happens.

eg:

```yaml
name: override_action_sample
description: override action sample
scope:
  - global
defaultActions: 
  - log
rules:
  - event: dropped_executable
    action:
     - webhook
```
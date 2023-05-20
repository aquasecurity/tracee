# Actions

## DefaultAction
Every policy must have a `defaultAction`. Actions are taken when there is match on some rule declared at the policy. 
The following actions are currently supported:

- `log` - output events in json format. The default path to file is stdout.
- `forward:http://url/fluent` - send events in json format using the Forward protocol to a Fluent receiver
- `webhook:http://url/webhook` - send events in json format to the webhook url

## Examples

### Log action

```yaml
name: log_sample_policy
description: log sample policy
scope:
  - global
defaultAction: log
rules:
  - event: dropped_executable
```

### Webhook action

```yaml
name: webhook_sample_policy
description: webhook_sample_policy
scope:
  - global
defaultAction: webhook:http://localhost:8080
rules:
  - event: dropped_executable
```

### Fluentd action

```yaml
name: webhook_sample_policy
description: webhook_sample_policy
scope:
  - global
defaultAction: forward:tcp://localhost:24224
rules:
  - event: dropped_executable
```

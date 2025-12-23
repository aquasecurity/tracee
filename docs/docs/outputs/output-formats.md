# Tracing Output Formats

It is possible to define how the events that Tracee collects should be displayed. This is done through the Tracee configuration. You can read more on configuration in the [Tracee installation guide.](../install/index.md)

Note that only one output format can be used in the Tracee configuration.

## Available Formats

The following examples will have to be added into a Tracee configuration file or CLI flags.

### JSON

Displays output events in json format. The default path to a file is stdout.

**yaml**

```yaml
output:
    destinations:
    - name: stdout_destination
      type: file
      format: json
      path: stdout
```

**cli**

```bash
tracee  --output destinations.stdout_destination.type=file \
        --output destinations.stdout_destination.format=json \
        --output destinations.stdout_destination.path=stdout
```

Note: the `name` is mandatory. `type` has `file` as a default value. `format` has `table` as a default value. `path` has `stdout` as a default value. The following configuration is valid as well

**yaml**

```yaml
output:
    destinations:
    - name: stdout_destination
      format: json
```

**cli**

```bash
tracee --output destinations.stdout_destination.format=json
```

!!! Tip
    A good tip is to pipe **tracee** json output to [jq](https://jqlang.github.io/jq/) tool, this way
    you can select fields, rename them, filter values, and much more!

### Webhook

This sends events in json format to the webhook url

Below is an example for configuring webhooks in the Tracee output section:

**yaml**

```yaml
output:
    destinations:
    - name: webhook1
      type: webhook
      url: http://localhost:8080?timeout=5s
      format: gotemplate=/path/to/template/test.tmpl

    - name: webhook2
      type: webhook
      url: http://localhost:9000
      format: gotemplate=/path/to/template/test.tmpl
```

**cli**

```bash
tracee  --output destinations.webhook1.type=webhook \
        --output destinations.webhook1.url=http://localhost:8080?timeout=5s \
        --output destinations.webhook1.format=gotemplate=/path/to/template/test.tmpl \
        --output destinations.webhook2.type=webhook \
        --output destinations.webhook2.url=http://localhost:9000 \
        --output destinations.webhook2.format=gotemplate=/path/to/template/test.tmpl
```

Note: `gotemplate=/path/to/template.tmpl` can be specified in `format` and as a parameter in the webhook url as well. 
Be aware that the url parameters has the priority on the format.

### Forward

This sends events to a FluentBit receiver. More information on FluentBit can be found in the [official documentation.](https://fluentbit.io/)

Below is an example for forwarding Tracee output: 

**yaml**

```yaml
output:
    destinations:
    - name: forward1
      type: forward
      url: tpc://user:password@localhost:24224?tag=tracee1
      format: gotemplate=/path/to/template/test.tmpl

    - name: forward2
      type: forward
      url: http://localhost:24224?tag=tracee2
      format: json
```

**cli**

```bash
tracee  --output destinations.forward1.type=forward \
        --output destinations.forward1.url=tpc://user:password@localhost:24224?tag=tracee1 \
        --output destinations.forward1.format=gotemplate=/path/to/template/test.tmpl \
        --output destinations.forward2.type=forward \
        --output destinations.forward2.url=http://localhost:24224?tag=tracee2 \
        --output destinations.forward2.format=json 
```

### Table

Displays output events in table format. The default path to a file is stdout.

**yaml**

```yaml
output:
    destinations:
    - name: stdout_table_destination
      type: file
      format: table
      path: stdout
```

**cli**

```bash
tracee  --output destinations.stdout_table_destination.type=file \
        --output destinations.stdout_table_destination.path=stdout \
        --output destinations.stdout_table_destination.format=table
```

or

**yaml**

```yaml
output:
    destinations:
    - name: stdout_table_destination
```

**cli**

```bash
tracee --output destinations.stdout_table_destination.format=table
```

### GOTEMPLATE

When authoring a Go template, the data source is Tracee's `v1beta1.Event` protobuf structure, which is defined in the [API protobuf definitions](https://github.com/aquasecurity/tracee/blob/main/api/v1beta1/event.proto).

**Common event fields:**
- `.timestamp` - Event timestamp (protobuf Timestamp with `.seconds` and `.nanos`)
- `.id` - Event ID (protobuf enum)
- `.name` - Event name (string)
- `.policies.matched` - Array of matched policy names
- `.workload.process` - Process information including:
  - `.workload.process.thread.name` - Process/thread name (comm)
  - `.workload.process.pid.value` - Process ID
  - `.workload.process.real_user.id.value` - User ID
  - `.workload.process.executable.path` - Executable path
- `.data` - Array of event-specific data fields (each with `.name` and typed `.value`)
- `.threat` - Threat information for signature detections

**Note:** For signature events, additional fields are available:

- `.threat.name` - Threat/signature name
- `.threat.description` - Threat description
- `.threat.properties.signatureID` - Signature ID
- `.detected_from` - The underlying event that triggered the signature

Go templates can utilize helper functions from [Sprig](http://masterminds.github.io/sprig/).

For example templates, see the templates directory in the source repository.

The following sections can be specified as part of go templates:

```yaml
output:
    destinations:
    - name: file_destination_1
      type: file
      format: gotemplate=/path/to/template_1.tmpl
      path: /path/to/file.log

    - name: file_destination_2
      type: file
      format: gotemplate=/path/to/template_2.tmpl
      path: /path/to/file_2.log
```

or the following flags can be used:

```bash
tracee  --output destinations.stdout_destination_1.type=file \
        --output destinations.stdout_destination_1.format=gotemplate=/path/to/template_1.tmpl \
        --output destinations.stdout_destination_1.path=/path/to/file.log \
        --output destinations.stdout_destination_2.type=file \
        --output destinations.stdout_destination_2.format=gotemplate=/path/to/template_2.tmpl \
        --output destinations.stdout_destination_2.path=/path/to/file_2.log \
```

## CLI flags

A destination can be configured using CLI flags as well. The format of a flag is `--output destinations.<destination_name>.<field_name>=<value>`.

### Available fields

| Field    | Usage                                                                                              | Default                                          |
| :------: | -------------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| type     | type of the destination. One of `file`, `webhook` or `forward`.                                    | file                                             |
| format   | format of the event. One of `json`, `table` or gotemplate=/path/to/template.yaml. | `table` for file, `json` for webhook and forward |
| url      | only for `webhook` and `forward` specify the destination url.                                      |                                                  |
| path     | only for `file` specify the file path to create, default to `stdout`.                              |                                                  |

Note: not specifying the `type` of destination will result in default value `file` which invalidates the presence of `url` field
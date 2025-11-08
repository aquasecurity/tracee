# Tracing Output Formats

It is possible to define how the events that Tracee collects should be displayed. This is done through the Tracee configuration. You can read more on configuration in the [Tracee installation guide.](../install/index.md)

Note that only one output format can be used in the Tracee configuration.

## Available Formats

The following examples will have to be added into a Tracee configuration file.

### JSON

Displays output events in json format. The default path to a file is stdout.

```yaml
output:
    destinations:
    - name: stdout_destination
      type: file
      format: json
      path: stdout
```

Note: the `name` is mandatory. `type` had `file` as a default value. `format` has `table` as a default value. 
`path` has `stdout` as a default value. The following configuration is valid as well

```yaml
output:
    destinations:
    - name: stdout_destination
      format: json
```

!!! Tip
    A good tip is to pipe **tracee** json output to [jq](https://jqlang.github.io/jq/) tool, this way
    you can select fields, rename them, filter values, and much more!

### Webhook

This sends events in json format to the webhook url

Below is an example for configuring webhooks in the Tracee output section:

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

Note: Please ensure that the respective fields will have to be uncommented.
Note: `gotemplate=/path/to/template.tmpl` can be specified in `format` and as a parameter in the webhook url as well. 
Be aware that the url parameters has the priority on the format.

### Forward

This sends events to a FluentBit receiver. More information on FluentBit can be found in the [official documentation.](https://fluentbit.io/)

Below is an example for forwarding Tracee output: 

```yaml
output:
    destinations:
    - name: forward1
      type: forward
      url: tpc://user:password@localhost:24224?tag=tracee1
      format: gotemplate=/path/to/template/test.tmpl

    - name: webhook2
      type: forward
      url: http://localhost:24224?tag=tracee2
      format: json
```

### Table

Displays output events in table format. The default path to a file is stdout.

```yaml
output:
    destinations:
    - name: stdout_destination
      type: file
      format: table
      path: stdout
```

or

```yaml
output:
    destinations:
    - name: stdout_table_destination
```

### Table (Verbose)

Displays the output events in table format with extra fields per event. The default path to a file is stdout.


```yaml
output:
    destinations:
    - name: stdout_destination
      type: file
      format: table-verbose
      path: stdout
```

or

```yaml
output:
    destinations:
    - name: stdout_table_destination
      format: table-verbose
```

### GOTEMPLATE

When authoring a Go template the data source is Tracee's `trace.Event` struct, which is defined in `https://github.com/aquasecurity/tracee/blob/main/types/trace/trace.go#L15`.

Go template can utilize helper functions from [Sprig](http://masterminds.github.io/sprig/).

For example templates, see [tracee/cmd/tracee-rules/templates](https://github.com/aquasecurity/tracee/tree/main/cmd/tracee-rules/templates).

The following sections can be specified as part of go templates:

```yaml
output:
    destinations:
    - name: stdout_destination
      type: file
      format: gotemplate=/path/to/template_1.tmpl
      path: /path/to/file.log

    - name: stdout_destination
      type: file
      format: gotemplate=/path/to/template_2.tmpl
      path: /path/to/file_2.log
```

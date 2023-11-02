<<<<<<< HEAD
# Output Formats
=======
# Tracing Output Formats

It is possible to define how the events that Tracee collects should be displayed. This is done through the Tracee configuration. You can read more on configuration in the [Tracee installation guide.](../install/index.md)

Note that only one output format can be used in the Tracee configuration.

## Examples
>>>>>>> 972efa3a (docs: rewrite output section)

The following examples will have to be added into a Tracee configuration file.

### Table

Displays output events in table format, which is the default. The default path to a file is stdout.

In the CLI:

```yaml
output:
    table:
        files:
            - /path/to/table1.out
            - /path/to/table2.out
```

### Table (Verbose)

Displays the output events in table format with extra fields per event. The default path to a file is stdout.

In the CLI:

```yaml
output:
    table-verbose:
        files:
            - stdout
```

### JSON

Displays output events in json format. The default path to a file is stdout.

```yaml
output:
    json:
        files:
            - stdout
```

!!! Tip
    A good tip is to pipe **tracee** json output to [jq](https://jqlang.github.io/jq/) tool, this way
    you can select fields, rename them, filter values, and many other things:
    > ```console
    > sudo ./dist/tracee -o json -o option:parse-arguments
    > -trace comm=ping | jq -c '. | {eventId, hostName, processName,
    > hostProcessId,UserId}'
    > ```


### GOTEMPLATE

When authoring a Go template the data source is Tracee's `trace.Event` struct, which is defined in `https://github.com/aquasecurity/tracee/blob/main/types/trace/trace.go#L15`.

Go template can utilize helper functions from [Sprig](http://masterminds.github.io/sprig/).

For example templates, see [tracee/cmd/tracee-rules/templates](https://github.com/aquasecurity/tracee/tree/main/cmd/tracee-rules/templates).

The following sections can be specified as part of go templates:

```
output:
    # gotemplate:
    #     template: /path/to/my_template1.tmpl
    #     files:
    #         - /path/to/output1.out
    #         - /path/to/output2.out
```

### Webhook

This sends events in json format to the webhook url

Below is an example for configuring webhooks in the Tracee output section:

```
output:
    # webhook:
    #     - webhook1:
    #         protocol: http
    #         host: localhost
    #         port: 8000
    #         timeout: 5s
    #         gotemplate: /path/to/template/test.tmpl
    #         content-type: application/json
    #     - webhook2:
    #         protocol: http
    #         host: localhost
    #         port: 9000
    #         timeout: 3s
    #         gotemplate: /path/to/template/test.tmpl
    #         content-type: application/json
```

Note: Please ensure that the respective fields will have to be uncommented.

### Forward

This sends events in json format using the Forward protocol to a Fluent receiver.

Below is an example for forwarding Tracee logs: 

```
output:
    # forward:
    #     - forward1:
    #         protocol: tcp
    #         user: user
    #         password: pass
    #         host: 127.0.0.1
    #         port: 24224
    #         tag: tracee1
    #     - forward2:
    #         protocol: udp
    #         user: user
    #         password: pass
    #         host: 127.0.0.1
    #         port: 24225
    #         tag: tracee2
```

Note: Please ensure that the respective fields will have to be uncommented.

### GOB

This outputs events in gob format. The default path to file is stdout.

```
output:
    gob:
        files:
            - /path/to/gob1.out
```
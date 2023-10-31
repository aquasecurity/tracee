# Output Formats and Logs

It is possible to manage the events gathered in Tracee logs through the CLI using the `--output` and `--log` flag. Users can control where and how to output events by specifying `--output <format>:<destination>`.  The `--output` flag can be used multiple times to output events.

Furthermore, the `--log` flag can be used to define what components of the gathered events should be appended to the Tracee output. However, for more fine-grained filters, please take a look at the [filtering section](../filters/index.md)

**The following output formats are supported:**

- `table[:/path/to/file]` - output events in table format (default). The default path to file is stdout.
- `table-verbose[:/path/to/file]` - output events in table format with extra fields per event. The default path to file is stdout.
- `json[:/path/to/file]` - output events in json format. The default path to file is stdout.
- `gob[:/path/to/file]` - output events in gob format. The default path to file is stdout.
- `gotemplate=/path/to/template[:/path/to/file]` - output events formatted using a given gotemplate file. The default path to file is stdout.
- `forward:http://url/fluent` - send events in json format using the Forward protocol to a Fluent receiver
- `webhook:http://url/webhook` - send events in json format to the webhook url
- `none` - ignore stream of events output, usually used with --capture

**For more information, have a look at the following sections:**

* Output [formats.](./output-options.md)
* Output [options](./output-options.md)
* Logging [options](./logging.md)


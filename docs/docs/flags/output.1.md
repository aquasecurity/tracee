---
title: TRACEE-OUTPUT
section: 1
header: Tracee Output Flag Manual
date: 2025/01
...

## NAME

tracee **\-\-output** - Control how and where output is printed

## SYNOPSIS

tracee **\-\-output** destinations.*name*.*field*=*value* | sort-events


## DESCRIPTION

The **\-\-output** flag allows you to control how and where the output is printed using destinations and output options.

### Destination Configuration

Output destinations are configured using the format: `--output destinations.<name>.<field>=<value>`

**Available Fields:**

- **type**: Type of the destination. One of `file`, `webhook`, or `forward`. Default: `file`
- **format**: Format of the event. One of `json`, `table`, or `gotemplate=/path/to/template`. Default: `table` for file, `json` for webhook and forward
- **path**: (file type only) File path to write output. Default: `stdout`
- **url**: (webhook and forward types) Destination URL

**Destination Types:**

- **file**: Output to a file or stdout in JSON, table, or custom template format
- **webhook**: Send events in JSON format to a webhook URL
- **forward**: Send events to a FluentBit receiver using the Forward protocol

### Output Options

- **sort-events**: Enable sorting events before passing them to output. May decrease overall program efficiency.

!!! Note
    The enrichment `parse-arguments` option is automatically enabled when using table format output. It does not need to be specified separately via `--enrichment parse-arguments`.

## EXAMPLES

- To output events as JSON to stdout using a destination named `stdout_json`:

  ```console
  --output destinations.stdout_json.format=json
  ```

- To output events as JSON to a file `/my/out.json`:

  ```console
  --output destinations.file_out.type=file --output destinations.file_out.format=json --output destinations.file_out.path=/my/out.json
  ```

- To output events using a Go template:

  ```console
  --output destinations.template_out.format=gotemplate=/path/to/my.tmpl
  ```

- To send events via the Forward protocol to a FluentBit receiver:

  ```console
  --output destinations.forward1.type=forward --output destinations.forward1.url=tcp://user:pass@127.0.0.1:24224?tag=tracee
  ```

- To send events to a webhook endpoint:

  ```console
  --output destinations.webhook1.type=webhook --output destinations.webhook1.url=http://webhook:8080
  ```

- To send events to a webhook with a timeout:

  ```console
  --output destinations.webhook1.type=webhook --output destinations.webhook1.url=http://webhook:8080?timeout=5s
  ```

## SEE ALSO

For comprehensive information about output configuration:

- **Output Formats**: See [Output Formats](../outputs/output-formats.md) for detailed format options
- **Output Options**: See [Output Options](../outputs/output-options.md) for all available output options
- **Event Structure**: See [Event Structure](../outputs/event-structure.md) for understanding event data
- **Outputs Overview**: See [Outputs Overview](../outputs/index.md) for complete output documentation

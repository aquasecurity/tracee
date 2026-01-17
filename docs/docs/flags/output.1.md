---
title: TRACEE-OUTPUT
section: 1
header: Tracee Output Flag Manual
date: 2025/01
...

## NAME

tracee **\-\-output** - Control how and where output is printed

## SYNOPSIS

tracee **\-\-output** destinations.*name*.*field*=*value* | option:{stack-addresses,exec-env,exec-hash[={inode,dev-inode,digest-inode}],parse-arguments,parse-arguments-fds} | sort-events


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

- **option:{stack-addresses,exec-env,exec-hash,parse-arguments,parse-arguments-fds}**: Augment output according to the given options. Multiple options can be specified, separated by commas.

  - **stack-addresses**: Include stack memory addresses for each event.
  - **exec-env**: When tracing execve/execveat, show the environment variables that were used for execution.
  - **exec-hash**: When tracing file related events, show the file hash (sha256).
    - Affected events: *sched_process_exec*, *shared_object_loaded*
    - **inode**: Recalculates the file hash if the inode's creation time (ctime) differs. Performant but not recommended; use only if container enrichment can't be enabled.
    - **dev-inode** (default): Better performance by associating ctime with device and inode pair. Recommended if correctness is preferred over performance without container enrichment.
    - **digest-inode**: Most efficient, keys hash to container image digest and inode pair. Requires container enrichment.
  - **parse-arguments**: Parse event arguments into human-readable strings instead of raw machine-readable values.
  - **parse-arguments-fds**: Enable parse-arguments and enrich file descriptors with file path translation. May cause pipeline slowdowns.

- **sort-events**: Enable sorting events before passing them to output. May decrease overall program efficiency.

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

- To output events as a table with stack addresses:

  ```console
  --output destinations.stdout_table.format=table --output option:stack-addresses
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

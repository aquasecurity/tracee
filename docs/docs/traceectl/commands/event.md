# Event Command Usage

The `event` command in **traceectl** is used for managing events within Tracee. It allows you to list, describe, enable, and disable various event types that Tracee can capture. Below is the usage guide for the `event` command and its subcommands.

## Usage

The `event` command is structured as follows:

```sh
traceectl event [subcommand] [flags]
```

## Subcommands

- **list**: Lists all available event definitions (built-in and plugin-defined), providing a brief summary of each.
  
  ```sh
  traceectl event list --format [json|table|template]
  ```

  - **`--format`** (`-f`): Specifies the output format (default is `table`). Supported formats are `json`, `table`, and `template`.

- **describe**: Retrieves detailed information about a specific event, including its fields, types, and other metadata.
  
  ```sh
  traceectl event describe <event_name> --format [json|table|template]
  ```

  - **`<event_name>`**: The name of the event to describe.
  - **`--format`** (`-f`): Specifies the output format (default is `table`).

- **enable**: Enables capturing of a specific event type in Tracee.
  
  ```sh
  traceectl event enable <event_name>
  ```

  - **`<event_name>`**: The name of the event to enable.

- **disable**: Disables capturing of a specific event type in Tracee.
  
  ```sh
  traceectl event disable <event_name>
  ```

  - **`<event_name>`**: The name of the event to disable.

## Flags

- **`--format`** (`-f`): Available with the `list` and `describe` subcommands. It specifies the format for the output. Supported values are:
  - `json`: Outputs event details in JSON format.
  - `table`: Outputs event details in a tabular view.
  - `template`: Uses a custom template for formatting the output.

## Examples

- **List All Events in JSON Format**
  
  ```sh
  traceectl event list --format json
  ```

- **Describe an Event**
  
  ```sh
  traceectl event describe execve --format table
  ```

- **Enable an Event**
  
  ```sh
  traceectl event enable execve
  ```

- **Disable an Event**
  
  ```sh
  traceectl event disable execve
  ```

## Summary

The `event` command in traceectl is a powerful tool for managing Tracee's event capabilities. Use the `list`, `describe`, `enable`, and `disable` subcommands to gain detailed insight and control over the events Tracee monitors.

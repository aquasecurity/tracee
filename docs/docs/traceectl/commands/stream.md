# Stream Command Usage

The `stream` command in **TraceeCtl** allows users to stream events directly from Tracee in real time. This command provides flexible output formats for better integration and readability.

## Usage

The `stream` command is structured as follows:

```sh
traceectl stream [policies...] [flags]
```

## Flags

- **`--format`** (`-f`): Specifies the format for the output. Supported values are:
  - `json`: Outputs event details in JSON format.
  - `table`: Outputs event details in a tabular view.

## Examples

- **Stream Events in JSON Format**
  
  ```sh
  traceectl stream --format json
  ```

- **Stream Events in Table Format**
  
  ```sh
  traceectl stream --format table
  ```

## Summary

The `stream` command in TraceeCtl is a useful tool for monitoring Tracee events in real time, with options for JSON or table output. Use this command to keep track of activities and ensure comprehensive observability for your system.

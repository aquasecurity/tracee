# Stream Command Usage

The `stream` command in **traceectl** allows users to stream events directly from Tracee in real time. This command provides flexible output formats for better integration and readability.

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

The `stream` command provides a real-time feed of Tracee events, allowing you to monitor system activity as it happens.

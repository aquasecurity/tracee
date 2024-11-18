# `format` Flag

The `--format` flag in **traceectl** is used to specify the output format for certain commands. Currently, this flag supports the following values for the `stream` and `event describe` commands:

- **`json`**: Outputs the data in JSON format, which is useful for automated processing or integration with other tools that consume JSON.
  
  Example:

  ```sh
  traceectl stream --format json
  ```

  In this example, the command lists all available events and outputs them in JSON format.

- **`table`**: Outputs the data in a tabular format, which is easier to read for users viewing the output directly in the terminal.
  
  Example:
  
  ```sh
  traceectl stream --format table
  ```

  In this example, the command streams events from Tracee and displays them in a table format, making it more human-readable.

The `--format` flag is helpful for customizing the output to meet different requirements, whether for readability or integration with other tools.

## Default Format

The default format for the `--format` flag is **table**. If no format is specified, the output will be displayed in a tabular format, which is more human-readable for most users.

# Stream Command Usage

The `stream` command in **traceectl** allows users to stream events directly from Tracee in real time. This command provides flexible output formats for better integration and readability.

## Usage

The `stream` command is structured as follows:

```sh
traceectl stream [flags]
```

- **`--policy`**: Specifies the policies to stream from (default is `""`).
- **`--format`**: Specifies the format (default is `table`).
- **`--server`**: Specifies the server unix socket path (default is `/var/run/tracee.sock`)
- **`--output`**: Specifies the output (default is `stdout`)

## Examples

- **Stream Events in JSON Format with a Specific Policy and different unix socket**
  
  ```sh
  traceectl stream --format json --server /tmp/tracee.sock --policy policy1 policy2
  ```

- **Stream Events to file**
  
  ```sh
  traceectl stream --output /path/to/file 
  ```

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

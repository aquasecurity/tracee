# Event Command Usage

The `event` command in **traceectl** is used for managing events within Tracee. It allows you to list, describe, enable, and disable various event types that Tracee can capture. Below is the usage guide for the `event` command and its subcommands.

## Usage

The `event` command is structured as follows:

```sh
traceectl event [subcommand] [flags]
```

## Subcommands

- **describe**: Retrieves detailed information about a specific **event** or **all the events**, including its fields, types, and other metadata.
  
  ```sh
  traceectl event describe <event_name>
  ```

  - **`<event_name>`**: The name of the event to describe.
  - **`--format`**: Specifies the format (default is `table`).
  - **`--server`**: Specifies the server unix socket path (default is `/var/run/tracee.sock`)
  - **`--output`**: Specifies the output (default is `stdout`)

- **enable**: Enables capturing of a specific event type in Tracee.
  
  ```sh
  traceectl event enable <event_name>
  ```

  - **`<event_name>`**: The name of the event to enable.
  - **`--server`**: Specifies the server unix socket path (default is `/var/run/tracee.sock`)
  - **`--output`**: Specifies the output (default is `stdout`)

- **disable**: Disables capturing of a specific event type in Tracee.
  
  ```sh
  traceectl event disable <event_name>
  ```

  - **`<event_name>`**: The name of the event to disable.
  - **`--server`**: Specifies the server unix socket path (default is `/var/run/tracee.sock`)
  - **`--output`**: Specifies the output (default is `stdout`)

## Examples

- **List All Events in JSON Format**
  
  ```sh
  traceectl event describe --format json
  ```

- **Describe an Event**
  
  ```sh
  traceectl event describe execve
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

The `event` command in traceectl is a powerful tool for managing Tracee's event capabilities. Use the, `describe`, `enable`, and `disable` subcommands to gain detailed insight and control over the events Tracee monitors.

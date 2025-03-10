# Version Command

The `version` command in **traceectl** provides detailed information about the current version of the tool. This includes the version number, build date, and other relevant metadata.

## Usage

To display the version information, use the following command:

``` bash
traceectl version
```

- **`--server`**: Specifies the server unix socket path (default is `/var/run/tracee.sock`)

This command will output details such as:

- **Version Number**: The current version of traceectl.
- **Commit Hash**: The Git commit hash associated with the current build (if applicable).

### Example Output

``` bash
v0.22.0
```

### Summary

- **`traceectl version`**: Displays detailed version information.

Use this command to verify your version or to gather information for troubleshooting purposes.

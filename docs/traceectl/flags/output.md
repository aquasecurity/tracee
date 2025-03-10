# `output` Flag

The `--output` flag is used to specify the destination for the command's output. This flag can be set to **stdout** or a file location.

- **stdout**: This is the default output destination, which means that the command's output will be displayed on the terminal. This is convenient for users who want to see immediate results directly in their console.
  
  Example:

  ```sh
  traceectl stream --output stdout
  ```

  In this example, the command outputs the streamed events to the terminal.

- **File Output**: You can use the `--output` flag to direct the output to a specific file. This is useful if you want to save the output for later analysis or for documentation purposes.
  
  Example:

  ```sh
  traceectl stream --output file:/path/to/output.txt
  ```

  In this example, the command saves the streamed events to the file located at `/path/to/output.txt`. This is especially helpful for logging purposes or when working with large amounts of data that need to be stored for further processing.

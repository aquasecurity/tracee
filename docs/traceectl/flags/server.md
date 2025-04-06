# `server` Flag

The `--server` flag in **traceectl** is used to specify the connection type that traceectl should use to communicate with the Tracee server. This connection type is **Unix socket** only.

- **Unix Socket**: This type of connection is generally used for local inter-process communication. It provides a secure and efficient means to connect to Tracee when both client and server are on the same machine.
  
  Example:

  ```sh
  traceectl --server /unix/socket/path.sock
  ```

  In this example, `/unix/socket/path.sock` is the Unix socket path where the Tracee server is listening. Using Unix sockets is beneficial for security and performance since it avoids the overhead associated with network communication.
  
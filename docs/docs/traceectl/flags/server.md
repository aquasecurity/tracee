# `server` Flag

The `--server` flag in **traceectl** is used to specify the connection type that traceectl should use to communicate with the Tracee server. This connection type can be either **Unix socket** or **TCP**.

- **Unix Socket**: This type of connection is generally used for local inter-process communication. It provides a secure and efficient means to connect to Tracee when both client and server are on the same machine.
  
  Example:

  ```sh
  traceectl --server unix:/unix/socket/path.sock
  ```

  In this example, `unix:/unix/socket/path.sock` is the Unix socket path where the Tracee server is listening. Using Unix sockets is beneficial for security and performance since it avoids the overhead associated with network communication.

- **TCP**: This type of connection allows traceectl to communicate with the Tracee server over a network. It is useful when traceectl and Tracee are running on different machines or when you need to connect to a remote Tracee instance.
  
  Example:

  ```sh
  traceectl --server tcp:4466
  ```

  In this example, `tcp:4466` is the address and port of the Tracee server. This is a typical setup for remote monitoring or when the server and client need to be distributed across different hosts.

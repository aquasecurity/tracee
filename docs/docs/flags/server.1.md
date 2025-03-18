---
title: TRACEE-SERVER
section: 1
header: Tracee Server Flag Manual
date: 2025/01
...

## NAME

tracee **\-\-server** - Configure server options and endpoints

## SYNOPSIS

tracee **\-\-server** <http-address=<host:port\>> | <grpc-address=<protocol:address\>> | grpc | metrics | healthz | pprof | pyroscope

## DESCRIPTION

The **\-\-server** flag allows you to configure server options and endpoints for Tracee. This unified flag replaces the deprecated individual server flags and provides better validation and error messages.

Server address options:

- **http-address=<host:port\>**: Start an HTTP server listening on the specified address. Used for metrics, healthz, pprof, and pyroscope endpoints.

- **grpc-address=<protocol:address\>**: Start a gRPC server listening on the specified protocol and address. Supported protocols are:
  - **tcp:<port\>**: TCP connection (e.g., tcp:4466). If no port is specified, defaults to 4466.
  - **unix:<socket_path\>**: Unix domain socket (e.g., unix:/tmp/tracee.sock). If no path is specified, defaults to /var/run/tracee.sock.

Server endpoint options (require HTTP server):

- **metrics**: Enable Prometheus metrics endpoint at /metrics. If no HTTP server is configured, defaults to localhost:3366.

- **healthz**: Enable health check endpoint at /healthz. If no HTTP server is configured, defaults to localhost:3366.

- **pprof**: Enable Go pprof debugging endpoints under /debug/pprof/. If no HTTP server is configured, defaults to localhost:3366.

- **pyroscope**: Enable Pyroscope profiling agent integration. If no HTTP server is configured, defaults to localhost:3366.

Other options:

- **grpc**: Enable gRPC server with default Unix socket at /var/run/tracee.sock. Equivalent to grpc-address=unix.

Multiple **\-\-server** flags can be specified to enable different combinations of servers and endpoints.

## EXAMPLES

- To enable gRPC server with default Unix socket:

  ```console
  --server grpc
  ```

- To enable gRPC server on a specific TCP port:

  ```console
  --server grpc-address=tcp:4466
  ```

- To enable gRPC server with custom Unix socket path:

  ```console
  --server grpc-address=unix:/tmp/tracee.sock
  ```

- To enable HTTP server with metrics endpoint:

  ```console
  --server http-address=:3366 --server metrics
  ```

- To enable metrics endpoint with default HTTP server:

  ```console
  --server metrics
  ```

- To enable multiple HTTP endpoints on custom address:

  ```console
  --server http-address=127.0.0.1:8080 --server metrics --server healthz --server pprof
  ```

- To enable both gRPC and HTTP servers:

  ```console
  --server grpc-address=unix:/var/run/tracee.sock --server http-address=:3366 --server metrics
  ```

- To enable all available endpoints:

  ```console
  --server http-address=:3366 --server grpc-address=tcp:4466 --server metrics --server healthz --server pprof --server pyroscope
  ```

## MIGRATION FROM DEPRECATED FLAGS

The **\-\-server** flag replaces the following deprecated flags:

| Deprecated Flag | New Server Flag Equivalent |
|---|---|
| `--metrics-endpoint` | `--server metrics` |
| `--healthz-endpoint` | `--server healthz` |
| `--pprof-endpoint` | `--server pprof` |
| `--pyroscope` | `--server pyroscope` |
| `--http-listen-addr=:3366` | `--server http-address=:3366` |
| `--grpc-listen-addr=tcp:4466` | `--server grpc-address=tcp:4466` |

Migration examples:

- Before: `--metrics-endpoint --grpc-listen-addr=tcp:4466`
- After: `--server metrics --server grpc-address=tcp:4466`

- Before: `--http-listen-addr=:8080 --metrics-endpoint --healthz-endpoint --pprof-endpoint`
- After: `--server http-address=:8080 --server metrics --server healthz --server pprof`

- Before: `--grpc-listen-addr=unix:/tmp/tracee.sock --metrics-endpoint`
- After: `--server grpc-address=unix:/tmp/tracee.sock --server metrics`

## DEFAULT BEHAVIOR

- If no **\-\-server** flags are specified, no servers are started.
- If endpoint flags (metrics, healthz, pprof, pyroscope) are specified without http-address, an HTTP server is automatically created on localhost:3366.
- If **grpc** flag is specified without grpc-address, a Unix socket server is created at /var/run/tracee.sock.
- If **grpc-address=tcp** is specified without a port, defaults to port 4466.
- If **grpc-address=unix** is specified without a path, defaults to /var/run/tracee.sock.
- Existing Unix socket files are automatically cleaned up before starting the gRPC server.

## SEE ALSO

**tracee**(1), **tracee-output**(1), **tracee-log**(1)

# Special: Healthz Endpoint

**tracee** supports a flag `--healthz` which enable a
`/healthz` endpoint that returns if `OK` if the process are healthy.

Example:

```console
tracee --healthz
curl http://localhost:3366/healthz
```

```text
OK
```

The port used is the default port `3366` for `tracee`.
It can be customized with the flag `--listen-addr`. 

Example:

```console
tracee --healthz --listen-addr=:8080
curl http://localhost:8080/healthz
```

```text
OK
```


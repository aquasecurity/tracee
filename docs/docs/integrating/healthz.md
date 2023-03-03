# Special: Healthz Endpoint

**tracee** supports a flag `--healthz` which enable a
`/healthz` endpoint that returns if `OK` if the process are healthy.

Example:

```
$ tracee --healthz
$ curl http://localhost:3366/healthz

OK
```

The port used is the default port `3366` for `tracee`.
It can be customized with the flag `--listen-addr`. 

Example:

```
$ tracee --healthz --listen-addr=:8080
$ curl http://localhost:8080/healthz

OK
```


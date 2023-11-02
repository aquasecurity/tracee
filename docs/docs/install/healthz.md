# Health Monitoring

Tracee can expose a `/healthz` endpoint that returns `OK` if the everything is healthy. This is a [common pattern](https://kubernetes.io/docs/reference/using-api/health-checks/) in Cloud Native and Kubernetes applications.  

Health monitoring endpoint is disabled by default, and can be enabled with the configuration:

```yaml
healthz: true
```

By default port `3366` is used. It can be customized with the configuration:

```yaml
listen-addr: 1234
```

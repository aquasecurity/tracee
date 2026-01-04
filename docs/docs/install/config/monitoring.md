# Monitoring

Tracee provides built-in monitoring capabilities to help you observe its performance and health status. Both features use the same HTTP server endpoint.

## Prometheus Metrics

Tracee exposes Prometheus metrics for performance monitoring of event production, consumption, and detection.

!!! Performance Attention
    Current Prometheus integration targets performance numbers for event
    production, consumption and detection. It does not target the detections
    themselves.

Prometheus scraping is **enabled by default in Kubernetes deployments** at `:3366/metrics`. For CLI usage, metrics must be explicitly enabled using the `--server metrics` flag.

### Configuration

**Enable metrics:**
```yaml
server:
  metrics: true
```

**Custom port:**
```yaml
server:
  http-address: :8080
  metrics: true
```

**CLI flags:**
```console
tracee --server metrics --server http-address=:8080
```

!!! Tip
    Check the [Grafana dashboard tutorial](../../../tutorials/deploy-grafana-dashboard.md) for a complete monitoring setup.

## Health Checks

Tracee can expose a `/healthz` endpoint that returns `OK` if everything is healthy. This follows the [common Kubernetes health check pattern](https://kubernetes.io/docs/reference/using-api/health-checks/).

Health monitoring is **disabled by default**.

### Configuration

**Enable health checks:**
```yaml
server:
  healthz: true
```

**Custom port:**
```yaml
server:
  http-address: :8080
  healthz: true
```

**CLI flags:**
```console
tracee --server healthz --server http-address=:8080
```

## Server Configuration

Both Prometheus metrics and health checks share the same HTTP server. Common configuration options:

| Option | Default | Description |
|--------|---------|-------------|
| `http-address` | `:3366` | HTTP server listen address |
| `metrics` | `true` | Enable Prometheus metrics endpoint |
| `healthz` | `false` | Enable health check endpoint |

### Example: Full Monitoring Setup

```yaml
server:
  http-address: :3366
  metrics: true
  healthz: true
```

This configuration makes available:
- Prometheus metrics: `http://localhost:3366/metrics`
- Health check: `http://localhost:3366/healthz`

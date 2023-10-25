# Kubernetes Config

## Configmap

Tracee ConfigMap exposed [tracee configuration](https://github.com/aquasecurity/tracee/blob/main/examples/config/global_config.yaml) to the deployment.

```
---
apiVersion: v1
kind: ConfigMap
metadata:
  labels:
    app.kubernetes.io/name: tracee
    app.kubernetes.io/component: tracee
    app.kubernetes.io/part-of: tracee
  name: tracee
data:
  config.yaml: |-
    cache:
        type: mem
        size: 512
    perf-buffer-size: 1024
    healthz: false
    metrics: true
    pprof: false
    pyroscope: false
    listen-addr: :3366
    log:
        level: info
    output:
        options:
            parse-arguments: true
        json:
            files:
                - stdout
```

## Customizing

You can customize specific options with the helm installation:

```
# setting blob-perf-event-size
helm install tracee aqua/tracee \
        --namespace tracee-system --create-namespace \
        --set config.blobPerfEventSize=1024


# setting a different output
helm install tracee aqua/tracee \
        --namespace tracee-system --create-namespace \
				--set config.output[0]=table
				--set config.output[1]=option:parse-arguments
```

Or you can pass a config file directly:

```
 helm install tracee aqua/tracee \
        --namespace tracee-system --create-namespace \
				--set-file traceeConfig=<path/to/config/file>
```

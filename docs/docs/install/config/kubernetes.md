# Configuring Tracee in Kubernetes

In Kubernetes, Tracee uses a ConfigMap, called `tracee` to make Tracee configuration accessible. The ConfigMap includes a data file called `config.yaml` with the desired configuration. For example:

```yaml
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
      - cache-type=mem
      - mem-cache-size=512
```

## Kubectl

You can use `kubectl` to interact with it:

View:

```shell
kubectl get cm tracee-config -n tracee
```

Edit:

```shell
kubectl edit cm tracee-config -n tracee
```

## Helm

You can customize specific options with the helm installation:

```
helm install tracee aqua/tracee \
        --namespace tracee --create-namespace \
        --set config.blobPerfEventSize=1024
```

or after installation:

```
helm install tracee aqua/tracee \
        --namespace tracee --create-namespace \
        --set config.output[0]=table \
```

or to provide a complete config file:

```
 helm install tracee aqua/tracee \
        --namespace tracee --create-namespace \
        --set-file traceeConfig=myconfig.yaml
```

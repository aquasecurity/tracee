# Using Grafana Alloy, Loki and Grafana to access Tracee Logs

By default, Tracee is emitting events to stdout. Users can then configure logging solutions to collect, store, and manage Tracee logs. 

This tutorial will showcase how to install and configure Grafana Alloy, Loki, Grafana and Prometheus to then access Tracee logs from the cluster in Grafana.

If you prefer the video tutorial, check out the tutorial below on the Aqua Open Source YouTube channel:

 Grafana Loki to access Tracee logs 
  [![Watch the video](../images/lokitut.png)](https://youtu.be/mMC9-yzbgpE?si=6C0emOEJJ5K4ACqB)

> **Note:** The video tutorial uses the deprecated Promtail agent. This written guide has been updated to use Grafana Alloy, which is the recommended replacement.

## Prerequisites

Please make sure to have the following tools installed in your CLI:

* Kubectl installed and connected to a Kubernetes cluster (any cluster will work for this purpose)
* The [Helm CLI](https://helm.sh/docs/) installed

Additionally, you might have the following Observability Stack already installed in your cluster, if not we will detail how to set it up further below in this guide: 

* [Prometheus](https://prometheus.io/)
* [Loki and Grafana Alloy](https://grafana.com/oss/loki/)
* [Grafana](https://grafana.com/oss/)

Alternatively, this tutorial showcases after the Tracee Installation section how to get an observability stack running with the above tools.

## Installing the Tracee Helm Chart and accessing logs

Right now, we cannot access any logs from our cluster since we do not have any application that actively produces logs.
Thus, we will install Tracee inside our cluster through the Tracee Helm Chart.

Add the Tracee Helm Chart:

```console
helm repo add aqua https://aquasecurity.github.io/helm-charts/
```

Update the repository list on Helm:

```console
helm repo update
```

Install the Tracee Helm Chart inside your Kubernetes cluster:

```console
helm install tracee aqua/tracee \
        --namespace tracee-system --create-namespace \
        --set hostPID=true
```

Now, ensure that Tracee is running inside the `tracee-system` namespace:

```console
kubectl get all -n tracee-system
```

Similar to Grafana Alloy, also for Tracee one pod should run on each node of the Kubernetes cluster.

### Accessing Tracee Logs

Generally, it is possible to access logs from the Tracee pods directly through kubectl:

```console
kubectl logs -f daemonset/tracee -n tracee-system
```

Next, open the Grafana Dashboard, on the left, go to "Explore". There, you should be able to select Loki as a Datasource.

Now, you can write log queries in LogQL to access the logs that are stored in the Tracee pods:

![Screenshot from Grafana, accessing Tracee logs through Loki](../images/loki.png)

## Installation of Observability Tools

We need to install an observability stack to access the logs of the pods inside our cluster. This will consist of:

- Grafana (for Dashboards and querying logs)
- Grafana Alloy for collecting logs from the pods on each node
- Loki, which is feeding the logs into Grafana

And since it is easier to install Grafana together with Prometheus, we are also going to install Prometheus.

If you are completely new to Loki, have a look at the following presentation:  [Learning the tricks of Grafana Loki for distributed logging at scale in a Kubernetes environment](https://youtu.be/jmtYUiBd_z0) 

### Grafana and Prometheus

First, we are going to install the kube-prometheus-stack chart with Prometheus and Grafana.

For this, we will need to specify some custom values that we will pass into the Helm Chart. 

Create a new file called `grafana-config.yaml` with the following content:

```yaml
prometheus:
  prometheusSpec:
    serviceMonitorSelectorNilUsesHelmValues: false
    serviceMonitorSelector: {}
    serviceMonitorNamespaceSelector: {}

grafana:
  sidecar:
    datasources:
      defaultDatasourceEnabled: true
  additionalDataSources:
    - name: Loki
      type: loki
      url: http://loki-gateway.monitoring:80
```

Next, we can install the kube-prometheus-stack chart into our cluster with the following commands:

Create a namespace for all the monitoring tools

```console
kubectl create ns monitoring
```

Add the kube-prometheus-stack Helm Chart to your Helm repository list:

```console
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
```

Ensure you have the latest version of all your repositories:

```console
helm repo update
```

Install the kube-prometheus-stack Helm Chart:

```console
helm upgrade --install prom prometheus-community/kube-prometheus-stack -n monitoring --values grafana-config.yaml
```

Lastly, confirm that all the pods have been created properly by querying the namespace:

```console
kubectl get all -n monitoring
```

### Grafana Alloy and Loki

Next, we need to install Grafana Alloy and Loki inside the cluster to actually access logs.

For this, first add the Grafana Helm Chart repository to your repository list:

```console
helm repo add grafana https://grafana.github.io/helm-charts
```

Update your Helm repository list:

```console
helm repo update
```

#### Installing Grafana Alloy

[Grafana Alloy](https://grafana.com/docs/alloy/latest/) is an OpenTelemetry Collector distribution that replaces the deprecated Promtail agent. It collects logs, metrics, and traces.

Create a file with the Helm Chart configuration for Grafana Alloy in an `alloy-config.yaml`:

```yaml
alloy:
  configMap:
    content: |
      // Discover pods in the cluster
      discovery.kubernetes "pods" {
        role = "pod"
      }

      // Relabel discovered pods for log collection
      discovery.relabel "pods" {
        targets = discovery.kubernetes.pods.targets

        rule {
          source_labels = ["__meta_kubernetes_namespace"]
          target_label  = "namespace"
        }

        rule {
          source_labels = ["__meta_kubernetes_pod_name"]
          target_label  = "pod"
        }

        rule {
          source_labels = ["__meta_kubernetes_pod_container_name"]
          target_label  = "container"
        }

        rule {
          source_labels = ["__meta_kubernetes_pod_label_app"]
          target_label  = "app"
        }
      }

      // Collect logs from discovered pods
      loki.source.kubernetes "pods" {
        targets    = discovery.relabel.pods.output
        forward_to = [loki.write.default.receiver]
      }

      // Send logs to Loki
      loki.write "default" {
        endpoint {
          url = "http://loki-gateway.monitoring:80/loki/api/v1/push"
        }
      }
```

Now we can install the Grafana Alloy Helm Chart inside our cluster:

```console
helm upgrade --install alloy grafana/alloy --values alloy-config.yaml -n monitoring
```

Make sure that Grafana Alloy is running the same number of pods as there are nodes on the cluster since Alloy has to run one pod per node:

```console
kubectl get pods -n monitoring -l app.kubernetes.io/name=alloy
```

For instance, if the cluster consists of three nodes, then there should be three Alloy pods inside of the monitoring namespace.

#### Installing Loki

Now, we can install Loki. Loki's job is to collect the logs from Grafana Alloy and forward them to Grafana.

We'll use the `loki` Helm chart (version 3.0 or higher), which replaces the deprecated `loki-distributed` chart.

Create a file called `loki-config.yaml` with the following content:

```yaml
loki:
  auth_enabled: false
  commonConfig:
    replication_factor: 1
  storage:
    type: filesystem
  schemaConfig:
    configs:
      - from: "2024-01-01"
        store: tsdb
        object_store: filesystem
        schema: v13
        index:
          prefix: index_
          period: 24h

singleBinary:
  replicas: 1

read:
  replicas: 0

write:
  replicas: 0

backend:
  replicas: 0

gateway:
  enabled: true
```

Install Loki with the following command:

```console
helm upgrade --install loki grafana/loki --values loki-config.yaml -n monitoring
```

> **Note:** The configuration above uses the single binary mode which is suitable for development and small deployments. For production environments, consider using the distributed mode with proper storage backends (S3, GCS, etc.).

At this point, the following pods should be running inside the Kubernetes cluster:

```text
NAME                                                     READY   STATUS    RESTARTS      AGE
prom-prometheus-node-exporter-l4cm4                      1/1     Running   0             22m
prom-kube-prometheus-stack-operator-84cf966ff5-96xdp     1/1     Running   0             22m
prom-kube-state-metrics-dc769cd87-fmrsk                  1/1     Running   0             22m
prom-grafana-6fdb45b4d5-2zxw7                            3/3     Running   0             22m
alertmanager-prom-kube-prometheus-stack-alertmanager-0   2/2     Running   1 (22m ago)   22m
prometheus-prom-kube-prometheus-stack-prometheus-0       2/2     Running   0             22m
alloy-xxxxx                                              1/1     Running   0             4m7s
loki-0                                                   1/1     Running   0             72s
loki-gateway-xxxxxxxxxx-xxxxx                            1/1     Running   0             72s
```

Since everything is running properly, we need to ensure that we can access Loki as a data source inside of Grafana.

### Accessing the Grafana Dashboard

For this, port-forward to Grafana:

```console
kubectl port-forward service/prom-grafana -n monitoring 3000:80
```

and open the Grafana UI on localhost:3000.

Here, you will need the username and the password:
username: admin
password: prom-operator

The password name is dependent on how you called the Helm Chart installation of the kube-prometheus-stack chart e.g. in our case, it was "prom".

Now navigate on Grafana to: Explore 
Here select Loki as a data source.

### Accessing Grafana on Remote Servers

If your Kubernetes cluster is running on a remote server (e.g., a cloud VM or a remote machine), you can use SSH tunneling to access the Grafana dashboard from your local machine.

#### Using SSH Port Forwarding

First, ensure you have started the kubectl port-forward command on the remote server:

```console
kubectl port-forward service/prom-grafana -n monitoring 3000:80
```

Then, from your local machine, create an SSH tunnel to the remote server:

```console
ssh -L 3000:localhost:3000 user@remote-server
```

Replace `user@remote-server` with your actual SSH connection details. This command forwards your local port 3000 to port 3000 on the remote server.

Now you can access the Grafana dashboard on your local machine by opening `http://localhost:3000` in your browser.

#### Alternative: Using SSH with Background Port Forwarding

If you want to run the SSH tunnel in the background:

```console
ssh -f -N -L 3000:localhost:3000 user@remote-server
```

- `-f` runs SSH in the background
- `-N` tells SSH not to execute a remote command (just forward ports)

To stop the background tunnel, you can find and kill the SSH process:

```console
# Find the process
ps aux | grep "ssh -f -N -L 3000"

# Kill it using the PID
kill <PID>
```

## Migration from Promtail (Legacy)

If you previously followed this tutorial using Promtail and the `loki-distributed` Helm chart, you can migrate to Grafana Alloy and the new Loki Helm chart by following these steps:

1. **Uninstall the old components:**

```console
helm uninstall promtail -n monitoring
helm uninstall loki -n monitoring
```

2. **Install the new components** following the instructions in this updated tutorial.

3. **Update your Grafana datasource** to point to the new Loki endpoint:
   - Old URL: `http://loki-loki-distributed-query-frontend.monitoring:3100`
   - New URL: `http://loki-gateway.monitoring:80`

For more information about the migration, see:
- [Migrate from Promtail to Grafana Alloy](https://grafana.com/docs/alloy/latest/set-up/migrate/from-promtail/)
- [Migrate from loki-distributed Helm chart](https://grafana.com/docs/loki/latest/setup/migrate/migrate-from-distributed/)

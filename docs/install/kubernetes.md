# Deploy on Kubernetes

In the [deploy/kubernetes](https://github.com/aquasecurity/tracee/blob/main/deploy/kubernetes) directory you can find Yaml files that deploys Tracee in a Kubernetes environment. This will deploy Tracee as a daemonset, alongside [falcosidekick](integrations.md#falcosidekick-webhook) so that you can conveniently consume Tracee's detections.

To install Tracee:

`kubectl create -f https://raw.githubusercontent.com/aquasecurity/tracee/main/deploy/kubernetes/tracee.yaml`.

## Webhoook Setting

You could use any message routing application. In the following section will be use Postee and Falcosidekick

### Postee

Install Postee in Kubernetes:

Download the manifest [here](https://github.com/aquasecurity/postee/tree/main/deploy/kubernetes).

The tracee.yaml using Postee

` --webhook http://postee-webhook:8080 --webhook-template ./templates/rawjson.tmpl --webhook-content-type application/json`
### Falcosidekick

Install Falcosidekick in Kubernetes:

`kubectl create -f deploy/kubernetes/falcosidekick
`

The tracee.yaml using Falcosidekick

` --webhook http://falcosidekick-webhook:2801 --webhook-template ./templates/falcosidekick.tmpl --webhook-content-type application/json`
## Platform support

This approach assumes that host nodes have either BTF available or kernel headers available under conventional location. see Tracee's [prerequisites](https://aquasecurity.github.io/tracee/dev/install/prerequisites/) for more info. For the major Kubernetes platforms this should work out-of-the-box, including GKE, EKS, AKS, minikube. 

## Consuming detections

[falcosidekick](https://github.com/falcosecurity/falcosidekick) is a useful webhook server that can be configured to connect to various "outputs" such as: Slack, Mattermost, Teams, Datadog, Prometheus, StatsD, Email, Elasticsearch, Loki, PagerDuty, OpsGenie, and many more. The YAML deployment also deploys falcosidekick alongside Tracee, so that you can conveniently consume the Tracee's detections. To configure falcosidekick you can edit the `webhook-cm.yaml` ConfigMap whis is expected to be in the [falcosidekick configuration format](https://github.com/falcosecurity/falcosidekick).



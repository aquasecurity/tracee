# Deploy on Kubernetes

In the [deploy/kubernetes](https://github.com/aquasecurity/tracee/blob/main/deploy/kubernetes) directory you can find Yaml files that deploys Tracee in a Kubernetes environment. This will deploy Tracee as a daemonset, alongside [falcosidekick](integrations.md#falcosidekick-webhook) so that you can conveniently consume Tracee's detections.

You could use any message routing application. In the following section will be use Postee and Falcosidekick.

## Install Tracee and Postee

Install Tracee with the webhook using Postee:

``` bash
kubectl create -f https://raw.githubusercontent.com/aquasecurity/tracee/main/deploy/kubernetes/tracee-postee/tracee.yaml
```

> More details about Postee settings with slack, jira, etc. [HERE](https://github.com/aquasecurity/postee/blob/main/cfg.yaml)

Install Postee:

``` bash
kubectl create -f https://raw.githubusercontent.com/aquasecurity/postee/main/deploy/kubernetes/postee.yaml
```

## Install Tracee and Falcosidekick


Install Tracee with the webhook using Falcosidekick:

`kubectl create -f deploy/kubernetes/tracee-falcosidekick
`

> More details about Falcosidekick settings with slack, jira, etc. [HERE](https://github.com/falcosecurity/falcosidekick/blob/master/config_example.yaml)

## Platform support

This approach assumes that host nodes have either BTF available or kernel headers available under conventional location. see Tracee's [prerequisites](https://aquasecurity.github.io/tracee/dev/install/prerequisites/) for more info. For the major Kubernetes platforms this should work out-of-the-box, including GKE, EKS, AKS, minikube. 

## Consuming detections

[falcosidekick](https://github.com/falcosecurity/falcosidekick) is a useful webhook server that can be configured to connect to various "outputs" such as: Slack, Mattermost, Teams, Datadog, Prometheus, StatsD, Email, Elasticsearch, Loki, PagerDuty, OpsGenie, and many more. The YAML deployment also deploys falcosidekick alongside Tracee, so that you can conveniently consume the Tracee's detections. To configure falcosidekick you can edit the `webhook-cm.yaml` ConfigMap is expected to be in the [falcosidekick configuration format](https://github.com/falcosecurity/falcosidekick).



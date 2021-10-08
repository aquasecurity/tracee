# Deploy on Kubernetes

In the [deploy/kubernetes](https://github.com/aquasecurity/tracee/blob/main/deploy/kubernetes) directory you can find Yaml files that deploys Tracee in a Kubernetes environment. This will deploy Tracee as a daemonset, alongside a message routing application that will help you consume the detections in your preferred way (e.g slack, email, JIRA and more).

## Platform support

This approach assumes that host nodes have either BTF available or kernel headers available under conventional location. see Tracee's [prerequisites](https://aquasecurity.github.io/tracee/dev/install/prerequisites/) for more info. For the major Kubernetes platforms this should work out-of-the-box, including GKE, EKS, AKS, minikube. 

## Choose how to consume detections

You could use any message routing application, but out-of-the-box Tracee lets you choose between [Postee](https://github.com/aquasecurity/postee) and [Falcosidekick](https://github.com/falcosecurity/falcosidekick).

To connect the Postee/Falcosidekick with your communication method of choice, update the `webhook-cm.yaml` ConfigMap according to tool's specific documentation.

- For Postee, see an example configuration here: https://github.com/falcosecurity/falcosidekick/blob/master/config_example.yaml
- For Falcosidekick, see and example configuration here: https://github.com/falcosecurity/falcosidekick/blob/master/config_example.yaml

## Install Tracee

To install Tracee with Postee, simply run:

``` bash
kubectl create -f deploy/kubernetes/tracee-postee
```

To install Tracee with Falcosidekick, simply run:

``` bash
kubectl create -f deploy/kubernetes/tracee-falcosidekick
```

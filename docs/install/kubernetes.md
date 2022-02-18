# Deploy on Kubernetes

In the [deploy/kubernetes](https://github.com/aquasecurity/tracee/blob/{{ git.tag }}/deploy/kubernetes) directory you
can find Yaml files to deploy Tracee in a Kubernetes environment. This will deploy Tracee as a DaemonSet, alongside
a message routing application that will help you consume the detections in your preferred way (e.g. slack, email, JIRA and more).

## Install Tracee

### With Postee

To install Tracee with [Postee](https://github.com/aquasecurity/postee), simply run:

``` bash
kubectl create \
  -f https://raw.githubusercontent.com/aquasecurity/postee/main/deploy/kubernetes/postee.yaml \
  -f https://raw.githubusercontent.com/aquasecurity/tracee/{{ git.tag }}/deploy/kubernetes/tracee-postee/tracee.yaml
```

You can edit the configMap `postee-config` the was created, see an example configuration here: https://github.com/aquasecurity/postee/blob/main/cfg.yaml.

You can also use the [Postee UI](https://github.com/aquasecurity/postee#postee-ui) to configure integrations.

### With Falcosidekick

To install Tracee with [Falcosidekick](https://github.com/falcosecurity/falcosidekick), simply run:

``` bash
kubectl create \
  -f https://raw.githubusercontent.com/aquasecurity/tracee/{{ git.tag }}/deploy/kubernetes/tracee-falcosidekick/falcosidekick.yaml \
  -f https://raw.githubusercontent.com/aquasecurity/tracee/{{ git.tag }}/deploy/kubernetes/tracee-falcosidekick/tracee.yaml
```

You can edit the configMap `falcosidekick-config` the was created, see an example configuration here: https://github.com/falcosecurity/falcosidekick/blob/master/config_example.yaml

## Platform Support

This approach assumes that host nodes have either BTF available or kernel headers available under conventional location.
See Tracee's [prerequisites](./../install/prerequisites.md) for more info. For the major Kubernetes platforms this should
work out-of-the-box, including GKE, EKS, AKS, minikube.

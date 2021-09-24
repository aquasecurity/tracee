# Deploy on Kubernetes

> NOTE This approach assumes that kernel headers are available on the Kubernetes nodes under conventional location, e.g /usr/src and /lib/modules. More details about [Minimal Requirements to run tracee in the Kubernetes nodes](https://aquasecurity.github.io/tracee/dev/install/prerequisites/)

 ``` bash
 kubectl create -f deploy/kubernetes
 ```

## Setting Webhook ConfigMap

This sample deploy use falcosidekick.tmpl and a config map for the falcosidekick settings (webhook-cm.yaml). Edit the ConfigMap with the respective values.

> NOTE `See the complete config file in` [falcosidekick](https://github.com/falcosecurity/falcosidekick)

# Supported Kubernetes Distributions

Currently, the following Kubernetes distributions are supported out of the box:

| Name | Version | Runtime
| --- | --- | --- |
GKE | v1.20.9-gke.1001 | docker
AKS | v1.20.9-aks | containerd://1.4.8+azure
EKS | v1.20.7-eks-135321 | docker
RKE2 | v1.21.5+rke2r1/rhel83 | containerd://1.4.8-k3s1


The following dev environments are also supported:

| Name | Version | Runtime
| --- | --- | --- |
minikube | v1.23.2 | docker
microk8s | v1.22.0 | docker
k3s | v1.21.4.k3s1 | docker


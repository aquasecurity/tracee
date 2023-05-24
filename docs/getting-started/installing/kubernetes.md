# Install **Tracee** on Kubernetes

In the [deploy/](https://github.com/aquasecurity/tracee/tree/{{ git.tag}}/deploy) directory you will find Yaml files to deploy Tracee
in a Kubernetes environment either with **Helm** or with a static yaml.

!!! Tip
    The **preferred** way to deploy **Tracee** is through its [Helm] chart!

[Helm]: https://helm.sh

1. Install **Tracee** using **Helm**

	1. Add Aqua chart repository:

		```console
		helm repo add aqua https://aquasecurity.github.io/helm-charts/
		helm repo update
		```

		or clone the Helm chart:

		```console
		git clone --depth 1 --branch {{ git.tag }} https://github.com/aquasecurity/tracee.git
		cd tracee
		```


	2. Install the chart from the Aqua chart repository:

		```console
		helm install tracee aqua/tracee \
				--namespace tracee-system --create-namespace
		```
  
		or install the Helm chart from a local directory:

		```console
		helm install tracee ./deploy/helm/tracee \
				--namespace tracee-system --create-namespace
		```

2. Install **Tracee** **Manually**

    To install Tracee 
    
    ```console
    kubectl create namespace tracee-system
    kubectl create -n tracee-system \
        -f https://raw.githubusercontent.com/aquasecurity/tracee/main/deploy/kubernetes/tracee/tracee.yaml
    ```

[HERE]: https://github.com/aquasecurity/postee/blob/main/cfg.yaml

## Platform Support

This approach assumes that host nodes have either BTF available or kernel
headers available under conventional location. See Tracee's
[prerequisites](../installing/prerequisites.md) for more info. For the major
Kubernetes platforms this should work out-of-the-box, including GKE, EKS, AKS,
minikube.

[deploy/kubernetes]:https://github.com/aquasecurity/tracee/blob/{{ git.tag }}/deploy/kubernetes

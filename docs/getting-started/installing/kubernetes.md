# Install **Tracee** on Kubernetes

In the [deploy/kubernetes] directory you will find Yaml files to deploy Tracee
in a Kubernetes environment. These files will deploy Tracee as a DaemonSet
alongside a message routing application ([Postee]) that will help you consume
the detections in your preferred way (e.g. Slack, E-mail, JIRA and more). 

[Postee]: https://github.com/aquasecurity/postee

!!! Note
    Although not optimal, you may consume **Tracee** detections through
    daemonset/tracee logs with `kubectl logs -f daemonset/tracee -n tracee-system`.

!!! Tip
    The **preferred** way to deploy **Tracee** is through its [Helm] chart!

[Helm]: https://helm.sh

1. Install **Tracee** using **Helm**

    1. Clone the Helm chart:

        ```text
        $ git clone --depth 1 --branch {{ git.tag }} https://github.com/aquasecurity/tracee.git
        $ cd tracee
        ```

    2. Install the Helm chart from a local directory:

        ```text
        $ helm repo add aqua-charts https://aquasecurity.github.io/helm-charts
        $ helm dependency update ./deploy/helm/tracee
        $ helm install tracee ./deploy/helm/tracee \
            --namespace tracee-system --create-namespace \
            --set hostPID=true \
            --set postee.enabled=true
        ```

2. Install **Tracee** **Manually**

    To install Tracee with [Postee](https://github.com/aquasecurity/postee),
    simply run:
    
    ```text
    $ kubectl create namespace tracee-system
    $ kubectl create -n tracee-system \
        -f https://raw.githubusercontent.com/aquasecurity/postee/main/deploy/kubernetes/postee.yaml \
        -f https://raw.githubusercontent.com/aquasecurity/tracee/{{ git.tag }}/deploy/kubernetes/tracee-postee/tracee.yaml
    ```

3. After Installation

    In order to choose how to make **Postee** deliver detection events from
    **Tracee**, you may edit the `postee-config` configMap. Follow
    [this example](https://github.com/aquasecurity/postee/blob/main/cfg.yaml).

    You can also use the [Postee UI] to configure integrations.

[HERE]: https://github.com/aquasecurity/postee/blob/main/cfg.yaml
[Postee UI]:https://github.com/aquasecurity/postee#postee-ui

## Platform Support

This approach assumes that host nodes have either BTF available or kernel
headers available under conventional location. See Tracee's
[prerequisites](../installing/prerequisites.md) for more info. For the major
Kubernetes platforms this should work out-of-the-box, including GKE, EKS, AKS,
minikube.

[deploy/kubernetes]:https://github.com/aquasecurity/tracee/blob/{{ git.tag }}/deploy/kubernetes

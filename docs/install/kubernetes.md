# Deploy on Kubernetes

> NOTE This approach assumes that kernel headers are available on the Kubernetes nodes under conventional location, e.g /usr/src and /lib/modules. More details about [Minimal Requirements to run tracee in the Kubernetes nodes](https://aquasecurity.github.io/tracee/install/prerequisites/)

 ``` bash
 kubectl create -f deploy/kubernetes
 ```

## Setting Webhook ConfigMap

This sample deploy use falcosidekick.tmpl and a config map for the falcosidekick settings (webhook-cm.yaml). Edit the ConfigMap with the respective values.

> NOTE `See the complete config file in` [falcosidekick](https://github.com/falcosecurity/falcosidekick)


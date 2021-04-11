# Deploy Tracee on Kubernetes

> NOTE This approach assumes that kernel headers are available on the Kubernetes nodes under conventional location, e.g /usr/src and /lib/modules. More details about [Minimal Requirements to run tracee in the Kubernetes nodes](https://aquasecurity.github.io/tracee/install/prerequisites/)

 ``` bash
 kubectl create -f deploy\kubernetes
 ```

## Setting templates - Optional

Create a ConfigMap that will hold the templates files for tracee-rules
 ``` bash
 kubectl create configmap tracee-templates --from-file=../../tracee-rules/templates
 ```

This sample deploy use falcosidekick.tmpl and a config map for the falcosidekick settings
> NOTE `See the complete config file in` [falcosidekick](https://github.com/falcosecurity/falcosidekick)

The service to integrate with tracee.
 
``` bash
https://tracee-webhook.default.svc.cluster.local:2801
````

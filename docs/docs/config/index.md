# Configuring Tracee

It is possible to configure the Tracee Kubernetes installation and CLI usage for every command through a configuration file. This way, the configuration file and its values can be applied every time Trcess runs.

Tracee can either be configured through:

* The `--config` flag in the CLI by providing the [Trivy config file](./cli.md)
* The [Tracee ConfigMap in Kubernetes](./kubernetes.md)
---
hide:
- toc
---
![Tracee Logo >](images/tracee.png)

👋 Welcome to Tracee Documentation! To help you get around, please notice the different sections at the top global menu:

- You are currently in the [Getting Started](./) section where you can find general information and help with first steps.
- In the [Tutorials](./tutorials/overview) section you can find step-by-step guides that help you accomplish specific tasks.
- In the [Docs](./docs/overview) section you can find the complete reference documentation for all of the different features and settings that Tracee has to offer.
- In the [Contributing](./contributing/overview) section you can find technical developer documentation and contribution guidelines.

<!-- links that differ between docs and readme -->
[installation]:./docs/install/
[docker-guide]:./docker.md
[kubernetes-guide]:./kubernetes.md
[prereqs]:./docs/install/prerequisites.md
<!-- everything below is copied from readme -->

Before moving on, please consider giving us a GitHub star ⭐️. Thank you!

## About Tracee

Tracee is a runtime security and observability tool that helps you understand how your system and applications behave.  
It is using [eBPF technology](https://ebpf.io/what-is-ebpf/) to tap into your system and expose that information as events that you can consume.  
Events range from factual system activity events to sophisticated security events that detect suspicious behavioral patterns.

To learn more about Tracee, check out the [documentation](https://aquasecurity.github.io/tracee/). 

## Quickstart

To quickly try Tracee use one of the following snippets. For a more complete installation guide, check out the [Installation section][installation].  
Tracee should run on most common Linux distributions and kernels. For compatibility information see the [Prerequisites][prereqs] page. MacOS users, please read it too.

### Using Docker

```shell
docker run --name tracee \
  --pid=host --cgroupns=host --privileged \
  -v /etc/os-release:/etc/os-release-host:ro \
  aquasec/tracee:latest
```

For a complete walkthrough please see the [Docker getting started guide][docker-guide].

### On Kubernetes

```shell
helm repo add aqua https://aquasecurity.github.io/helm-charts/
helm repo update
helm install tracee aqua/tracee --namespace tracee --create-namespace
```

```shell
kubectl logs --follow --namespace tracee daemonset/tracee
```

For a complete walkthrough please see the [Kubernetes getting started guide][kubernetes-guide].

## Contributing
  
Join the community, and talk to us about any matter in the [GitHub Discussions](https://github.com/aquasecurity/tracee/discussions) or [Slack](https://slack.aquasec.com).  
If you run into any trouble using Tracee or you would like to give use user feedback, please [create an issue.](https://github.com/aquasecurity/tracee/issues)

Find more information on [contribution documentation](./contributing/overview/).

## More about Aqua Security

Tracee is an [Aqua Security](https://aquasec.com) open source project.  
Learn about our open source work and portfolio [here](https://www.aquasec.com/products/open-source-projects/).

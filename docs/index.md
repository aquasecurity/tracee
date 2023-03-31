---
hide:
- toc
---
![Tracee Logo >](images/tracee.png)

Before moving on, please consider giving us a star ⭐️
by clicking the button at the top of the [GitHub page](https://github.com/aquasecurity/tracee/)

# Tracee Documentation

👋 Welcome to Tracee Documentation! To help you get around, please notice the different sections at the top global menu:

- You are currently in the [Getting Started](./) section where you can find general information and help with first steps.
- In the [Tutorials](./tutorials/overview) section you can find step-by-step guides that help you accomplish specific tasks.
- In the [Docs](./docs) section you can find the complete reference documentation for all of the different features and settings that Tracee has to offer.
- In the [Contributing](./contributing) section you can find technical developer documentation and contribution guidelines.

# Tracee: Runtime Security and Forensics using eBPF

Tracee uses eBPF technology to tap into your system and give you access to hundreds of events that help you understand how your system behaves.
In addition to basic observability events about system activity, Tracee adds a collection of sophisticated security events that expose more advanced behavioral patterns. You can also easily add your own events using the popular [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) language.
Tracee provides a rich filtering mechanism that allows you to eliminate noise and focus on specific workloads that matter most to you.

To learn more about Tracee, check out the [documentation](https://aquasecurity.github.io/tracee/).

## Quickstart

You can easily start experimenting with Tracee using the Docker image as follows:

```console
docker run \
  --name tracee --rm -it \
  --pid=host --cgroupns=host --privileged \
  -v /etc/os-release:/etc/os-release-host:ro \
  -e LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host \
  aquasec/tracee:latest
```

To learn how to install Tracee in a production environment, [check out the Kubernetes guide](./getting-started/kubernetes-quickstart).


## Pipeline protection with Tracee

Tracee can be used to protect GitHub Actions workflows against supply chain attacks. See the [tracee-action](https://github.com/aquasecurity/tracee-action) project for more information.

---

Tracee is an [Aqua Security](https://aquasec.com) open source project.  
Learn about our open source work and portfolio [Here](https://www.aquasec.com/products/open-source-projects/).  
Join the community, and talk to us about any matter in [GitHub Discussion](https://github.com/aquasecurity/tracee/discussions) or [Slack](https://slack.aquasec.com).  

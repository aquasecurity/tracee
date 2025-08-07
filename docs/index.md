---
hide:
- toc
---
![Tracee Logo >](images/tracee.png)

👋 Welcome to Tracee Documentation! To help you get around, please notice the different sections at the top global menu:

- You are currently in the [Getting Started](index.md) section where you can find general information and help with first steps.
- In the [Tutorials](tutorials/overview.md) section you can find step-by-step guides that help you accomplish specific tasks.
- In the [Docs](docs/overview.md) section you can find the complete reference documentation for all of the different features and settings that Tracee has to offer.
- In the [Contributing](contributing/overview.md) section you can find technical developer documentation and contribution guidelines.

<!-- links that differ between docs and readme -->
[installation]:./docs/install/index.md
[docker-guide]:./docs/install/docker.md
[kubernetes-guide]:./docs/install/kubernetes.md
[prereqs]:./docs/install/prerequisites.md
[macfaq]:./docs/advanced/mac.md
<!-- everything below is copied from readme -->

Before moving on, please consider giving us a GitHub star ⭐️. Thank you!
 
## About Tracee

Tracee is a runtime security and observability tool that helps you understand how your system and applications behave using [eBPF technology](https://ebpf.io/what-is-ebpf/). It provides deep visibility into Linux systems by monitoring system calls, network activity, and file operations in real-time.

### What Tracee Does

- **🔍 System Monitoring**: Tracks system calls, process execution, file operations, and network activity
- **🛡️ Security Detection**: Identifies suspicious behavior patterns and potential security threats
- **📊 Observability**: Provides detailed insights into application and system behavior
- **🚨 Real-time Alerts**: Generates events for immediate threat detection and response

### Key Features

- **Zero Code Changes**: Monitor existing applications without modification
- **Low Overhead**: Minimal performance impact using efficient eBPF programs
- **Container Aware**: Native support for containerized environments and Kubernetes
- **Flexible Policies**: Customize what to monitor and how to respond to events
- **Rich Event Data**: Detailed context including process lineage, file paths, and network connections

### Use Cases

- **Security Monitoring**: Detect malware, privilege escalation, and suspicious activity
- **Compliance**: Monitor file access, data exfiltration, and system changes
- **Troubleshooting**: Debug application issues and system behavior
- **Forensics**: Investigate security incidents with detailed audit trails

## Quickstart

To quickly try Tracee use one of the following snippets. For a more complete installation guide, check out the [Installation section][installation].  
Tracee should run on most common Linux distributions and kernels. For compatibility information see the [Prerequisites][prereqs] page. Mac users, please read [this FAQ][macfaq].

### Using Docker

```shell
docker run --name tracee -it --rm \
  --pid=host --cgroupns=host --privileged \
  -v /etc/os-release:/etc/os-release-host:ro \
  -v /var/run:/var/run:ro \
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

## Next Steps

After trying the quickstart, here's how to dive deeper:

### 🎯 For Security Analysts
- **[Events Documentation](docs/events/index.md)**: Learn about security events and signatures
- **[Policies Guide](docs/policies/index.md)**: Create custom detection rules
- **[Kubernetes Tutorial](tutorials/k8s-policies.md)**: Monitor containerized workloads

### 🛠️ For DevOps Engineers
- **[Installation Guide](docs/install/index.md)**: Production deployment options
- **[Configuration](docs/install/config/index.md)**: Customize Tracee for your environment
- **[Outputs](docs/outputs/index.md)**: Integrate with your monitoring stack

### 👨‍💻 For Developers
- **[Custom Events](docs/events/custom/overview.md)**: Create your own detection logic
- **[Contributing Guide](contributing/overview.md)**: Help improve Tracee
- **[Building from Source](contributing/building/building.md)**: Development setup

## Contributing
  
Join the community, and talk to us about any matter in the [GitHub Discussions](https://github.com/aquasecurity/tracee/discussions) or [Slack](https://slack.aquasec.com).  
If you run into any trouble using Tracee or you would like to give us user feedback, please [create an issue.](https://github.com/aquasecurity/tracee/issues)

Find more information on [contribution documentation](contributing/overview.md).

## More about Aqua Security

Tracee is an [Aqua Security](https://aquasec.com) open source project.  
Learn about our open source work and portfolio [here](https://www.aquasec.com/products/open-source-projects/).

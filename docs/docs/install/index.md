# Installing Tracee

This guide walks you through installing and setting up Tracee in your environment.

## 📋 Before You Start

### System Requirements

Before installing Tracee, ensure your system meets the necessary requirements:

- **[Prerequisites](./prerequisites.md)** - Operating system, kernel version, BTF, and capability requirements
- **[Kernel Symbols](./kernel-symbols.md)** - Kernel symbol table details and configuration
- **[OS Requirements](./os-requirements.md)** - OS release file and kernel config requirements
- **[Capabilities](./capabilities.md)** - Running Tracee with proper Linux capabilities
- **[LSM BPF Support](./lsm-support.md)** - Linux Security Module BPF support (optional)
- **[Mac Users FAQ](./mac-faq.md)** - Running Tracee on macOS (spoiler: you'll need a Linux VM or container)

!!! tip "Quick Compatibility Check"
    Tracee requires Linux kernel 5.4+ (or 4.18 for RHEL 8) with BTF support. Check `/sys/kernel/btf/vmlinux` exists and `/proc/kallsyms` is available.

## 🚀 Installation Methods

### Download Options

Tracee is available through multiple distribution channels:

1. **Binary releases**: [GitHub Releases](https://github.com/aquasecurity/tracee/releases)
2. **Container images**: [Docker Hub - aquasec/tracee](https://hub.docker.com/r/aquasec/tracee)
3. **Helm charts**: Aqua Security's Helm repository - `https://aquasecurity.github.io/helm-charts/`

Tracee may also be available in various community-managed package managers.

### Quick Start Guides

Choose your deployment method:

- **[Docker Installation](./docker.md)** - Run Tracee as a Docker container (fastest way to get started)
- **[Kubernetes Installation](./kubernetes.md)** - Deploy Tracee on Kubernetes clusters with Helm

## ⚙️ Post-Installation Setup

After installing Tracee, configure it for your environment:

### Container Integration

- **[Container Runtime Detection](./container-engines.md)** - Configure Tracee to detect and enrich events from Docker, Containerd, CRI-O, or Podman

### Configuration

- **[Configuration Guide](./config/index.md)** - Complete configuration reference for CLI and Kubernetes deployments
  - [CLI Configuration](./config/cli.md) - Configure Tracee command-line tool
  - [Kubernetes Configuration](./config/kubernetes.md) - Configure Tracee in Kubernetes

### Monitoring & Observability

- **[Health Monitoring](./healthz.md)** - Enable health check endpoints for monitoring
- **[Prometheus Integration](./prometheus.md)** - Enable metrics collection and export to Prometheus

## 🔍 Next Steps

After installation:

1. **Learn about policies**: Read the [Policies Guide](../policies/index.md) to define what to monitor
2. **Explore events**: Check out [Events Documentation](../events/index.md) to understand available events
3. **Configure outputs**: Set up [Output formats](../outputs/index.md) for your monitoring stack

## 💡 Troubleshooting

Having issues during installation or setup? Check our [Troubleshooting Guide](../troubleshooting.md) for common solutions.

For help and support, visit:

- [GitHub Discussions](https://github.com/aquasecurity/tracee/discussions)
- [Slack Community](https://slack.aquasec.com)

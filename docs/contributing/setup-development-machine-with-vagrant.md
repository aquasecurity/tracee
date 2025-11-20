# Setup Development Machine with Vagrant

[HashiCorp Vagrant] leverages a declarative configuration file, which describes
all software requirements, packages, operating system configuration, and users
to provide the same development environment for everyone.

The [Vagrantfile](https://github.com/aquasecurity/tracee/blob/main/Vagrantfile) describes a cross-platform QEMU-based virtual machine optimized for building Tracee from the [Getting Started](../index.md) guides. It supports both Linux and macOS hosts with hardware acceleration for optimal performance.

This allows developers involved in the project to check out the code, run `vagrant up`, and be on their way with a fully configured [cloud-image/ubuntu-24.04] development environment.

## Features

- **Cross-platform support**: Linux (KVM) and macOS (HVF) with automatic hardware acceleration detection
- **Optimized shared folders**: Platform-specific 9p filesystem implementation for best performance
- **Flexible configuration**: Easily customize CPU, memory, and acceleration settings
- **Automatic error handling**: Comprehensive validation and user-friendly error messages

## Prerequisites

- [Vagrant] (2.2+)
- [QEMU] - Cross-platform virtualization (recommended)
  - **Linux**: `sudo pacman -S qemu-full` (Arch) or `sudo apt install qemu-system-x86` (Ubuntu)
  - **macOS**: `brew install qemu`
- [vagrant-qemu plugin] - Install with: `vagrant plugin install vagrant-qemu`

**Note**: The Vagrantfile uses QEMU for better cross-platform compatibility and performance. Hardware acceleration (KVM on Linux, HVF on macOS) is automatically detected and used when available.

## Clone the Tracee Repository

Clone the Tracee repository to your local machine. This repository contains the Vagrantfile.

```bash
git clone https://github.com/aquasecurity/tracee.git
```

## Navigate to the Tracee Directory

Open a terminal and navigate to the directory containing the `Vagrantfile` within the cloned Tracee repository (`tracee/`)

```bash
cd tracee
```

## Configure VM Type (Optional)

The VM can be provisioned for either a `dev` or `test` environment. The `dev` environment includes additional tools like MicroK8s, kubectl, and Helm.

- **Development Environment:** Full development environment (Default)

  ```bash
  export VM_TYPE=dev
  ```

- **Testing Environment:**  Smaller vagrant machine without k8s cumbersome to avoid conflicts with specific tests.

  ```bash
  export VM_TYPE=test
  ```

**Important:** There are two ways to use a custom `VM_TYPE`:

**Option 1: Export the environment variable (recommended)**
```bash
# Export once, then use normal vagrant commands
export VM_TYPE=test
vagrant up
vagrant ssh
vagrant halt
vagrant destroy
```

**Option 2: Prefix each command (if not exported)**
```bash
# Include VM_TYPE in every command if not exported
VM_TYPE=test vagrant up
VM_TYPE=test vagrant ssh
VM_TYPE=test vagrant halt
VM_TYPE=test vagrant destroy
```

Without setting `VM_TYPE`, vagrant defaults to the `dev` environment. If you use the prefix method (Option 2) and forget to include `VM_TYPE` in a command, vagrant may operate on the wrong VM or give "VM not found" errors.

> **💡 Tip**: Use `export VM_TYPE=test` at the beginning of your session to avoid repeating it in every command.

## Configure VM Settings (Optional)

Customize the VM's configuration by setting the following environment variables:

### Resource Allocation

- `VM_CPUS`: Number of virtual processors. Defaults to half of the host's processors. Example:

  ```bash
  export VM_CPUS=4
  ```

- `VM_MEM`: Memory in gigabytes. Defaults to 8GB. Example:

  ```bash
  export VM_MEM=16
  ```

### Hardware Acceleration

- `VM_ACCEL`: Force specific acceleration type. Options vary by host OS:

  **Linux:**
  ```bash
  export VM_ACCEL=kvm   # KVM acceleration (fast)
  export VM_ACCEL=tcg   # Software emulation (slow)
  ```

  **macOS:**
  ```bash
  export VM_ACCEL=hvf   # HVF acceleration (fast)
  export VM_ACCEL=tcg   # Software emulation (slow)
  ```

  If not specified, the optimal acceleration method is automatically detected.

## Start the VM

### Basic Usage

Run the following command to start the VM with default settings:

```bash
vagrant up
```

### Custom Configuration Examples

You can combine environment variables for custom configurations:

```bash
# Test VM with custom resources
VM_TYPE=test VM_CPUS=4 VM_MEM=4 vagrant up

# Force software emulation (useful for troubleshooting)
VM_ACCEL=tcg vagrant up

# High-performance development VM
VM_TYPE=dev VM_CPUS=8 VM_MEM=16 vagrant up
```

### Changing Acceleration After VM Creation

To change hardware acceleration, you must halt and restart the VM:

```bash
# Switch to software emulation
vagrant halt && VM_ACCEL=tcg vagrant up

# Switch back to hardware acceleration (Linux)
vagrant halt && VM_ACCEL=kvm vagrant up

# Switch back to hardware acceleration (macOS)
vagrant halt && VM_ACCEL=hvf vagrant up
```

**Note:** `vagrant reload` does NOT apply acceleration changes.

Vagrant will download the [cloud-image/ubuntu-24.04] base box, provision the VM, and install all required dependencies including clang19. This process may take some time on first run.

## Accessing the VM

Once the VM is up and running, you can access it via SSH:

```bash
vagrant ssh
```

This will place you in the `/vagrant` directory inside the VM, which is synced with the Tracee directory on your host machine.

### Shared Folder Implementation

The VM uses a sophisticated shared folder system that varies by host OS:

- **Linux**: Direct 9p mount with UID/GID mapping for optimal performance
- **macOS**: 9p + bindfs overlay for proper ownership mapping

**Performance Note for macOS users:** File operations may be slower due to the bindfs overlay. For large Git operations or extensive file processing, consider running them outside the VM.

## Build and Run Tracee

You can now build Tracee within the VM using the provided Makefile. Consult the Tracee documentation for specific build instructions.
[Building Tracee Documentation](./building/building.md)

## Running Tests in the VM

Tracee's integration and e2e tests require root privileges and can affect your system. The recommended approach is to run them in an isolated VM environment.

### Quick Start

Run all tests automatically in an isolated VM:

```bash
./tests/run-vm-tests.sh
```

This will:
- Start a test VM (`VM_TYPE=test`)
- Build Tracee and run all test suites
- Show results and clean up automatically

**Run specific tests:**

```bash
# Run only integration tests
./tests/run-vm-tests.sh --integration

# Run only unit tests
./tests/run-vm-tests.sh --unit

# Combine test suites
./tests/run-vm-tests.sh --integration --e2e-inst
```

### Detailed Testing Guide

For comprehensive information including:
- Prerequisites and installation
- Manual testing workflows
- Troubleshooting and debugging
- Advanced usage examples

See: **[VM Testing Guide](vm-testing.md)**

## Stopping the VM

To stop the VM, use:

  ```bash
  vagrant halt
  ```

## Destroying the VM

To completely remove the VM, use:

  ```bash
  vagrant destroy
  ```

## Troubleshooting

- **QEMU Installation Issues**: Ensure QEMU is properly installed and the vagrant-qemu plugin is active. Run `vagrant plugin list` to verify.

- **Shared Folder Issues**: QEMU uses 9p filesystem for sharing. If sync issues occur, try reloading the VM with `vagrant reload`.

- **Networking Issues**: If you have trouble accessing forwarded ports, check your firewall settings on both the host and guest machines.

- **Performance**: For best performance, ensure hardware acceleration is available (KVM on Linux, HVF on macOS). Check with `egrep -c '(vmx|svm)' /proc/cpuinfo` on Linux.

**HVF not available (macOS):**
```bash
# Check if HVF is supported
sysctl -n kern.hv_support
# Ensure you're on macOS 10.10+ with Intel CPU or Apple Silicon
```

**Fallback to software emulation:**
If hardware acceleration is not available, the VM automatically falls back to TCG software emulation. This is slower but functional.

### Shared Folder Issues

**Files not visible in `/vagrant`:**
```bash
# Check mount status inside VM
mount | grep vagrant

# For Linux hosts - check direct 9p mount
mount | grep 9p

# For macOS hosts - check bindfs mount
mount | grep bindfs
```

**Permission issues (macOS):**
```bash
# Inside VM, check ownership
ls -la /vagrant

# Should show vagrant:vagrant (1000:1000)
# If not, check systemd mount services (macOS hosts):
sudo systemctl status mnt-shared.mount
sudo systemctl status vagrant.mount
```

### Performance Issues

**Slow file operations (macOS):**
- This is expected due to bindfs overlay
- Consider running large operations outside VM
- Use Git inside VM for better performance with large repositories

**VM performance is slow:**
- Ensure hardware acceleration is enabled
- Check: `vagrant ssh` then `cat /proc/cpuinfo | grep flags` for virtualization features
- Increase VM resources: `VM_CPUS=8 VM_MEM=16 vagrant up`

### Network and Port Issues

**Port conflicts:**
```bash
# Check actual forwarded ports
vagrant ssh-config
ps aux | grep qemu-system | grep hostfwd
```

**SSH connection issues:**
```bash
# Force VM restart
vagrant halt --force && vagrant up

# Check VM status
vagrant status
```

### General Issues

**VM stuck or unresponsive:**
```bash
# Force halt and restart
vagrant halt --force
vagrant up
```

**Provisioning failures:**
```bash
# Re-run provisioning
vagrant provision

# Or destroy and recreate
vagrant destroy -f && vagrant up
```

**QEMU/plugin issues:**
```bash
# Ensure vagrant-qemu plugin is installed
vagrant plugin list | grep qemu

# Reinstall if needed
vagrant plugin uninstall vagrant-qemu
vagrant plugin install vagrant-qemu
```

[HashiCorp Vagrant]: https://www.vagrantup.com/
[cloud-image/ubuntu-24.04]: https://portal.cloud.hashicorp.com/vagrant/discover/cloud-image
[QEMU]: https://www.qemu.org/
[vagrant-qemu plugin]: https://github.com/ppggff/vagrant-qemu
[Hypervisor]: https://en.wikipedia.org/wiki/Hypervisor

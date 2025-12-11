# Running Tracee Tests in a VM

This guide explains how to run Tracee integration and end-to-end (e2e) tests in an isolated Vagrant VM environment, ensuring your host system remains unaffected by privileged operations, eBPF programs, and Docker containers.

## Why Use a VM for Testing?

Tracee's integration and e2e tests require:
- **Root privileges** for eBPF operations
- **Kernel access** for loading eBPF programs
- **Docker** for container-related tests
- **System modifications** that could affect your host

Running tests in a VM provides complete isolation, ensuring:
- No sudo required on your host machine
- eBPF operations safely contained
- Docker containers isolated from host
- No risk of affecting your development environment

## Prerequisites

### Required Software

1. **Vagrant** (2.2+)
   ```bash
   # Check if installed
   vagrant --version

   # Install on various platforms
   # See: https://www.vagrantup.com/downloads
   ```

2. **QEMU** (recommended) or VirtualBox
   ```bash
   # QEMU (recommended - better performance and compatibility)
   # Manjaro/Arch
   sudo pacman -S qemu-full

   # Ubuntu/Debian
   sudo apt-get install qemu-system-x86

   # macOS
   brew install qemu
   ```

3. **Vagrant QEMU Plugin** (if using QEMU)
   ```bash
   vagrant plugin install vagrant-qemu
   ```

### System Requirements

- **CPU**: 4+ cores recommended (VM uses 4 by default)
- **RAM**: 8GB+ recommended (VM uses 8GB by default)
- **Disk**: ~20GB free space for VM and build artifacts
- **Network**: Internet access for downloading VM image and dependencies

## Quick Start

The simplest way to run all tests:

```bash
cd /path/to/tracee
./tests/run-vm-tests.sh
```

This will:
1. ✓ Check prerequisites (Vagrant, hypervisor)
2. ✓ Start a test VM (Ubuntu 24.04 with eBPF kernel)
3. ✓ Install all dependencies automatically
4. ✓ Build Tracee from source
5. ✓ Run all test suites (unit, integration, e2e)
6. ✓ Collect logs to `tests/vm-test-logs/`
7. ✓ Destroy VM on success (or preserve on failure)

**First run takes 10-15 minutes** (downloads VM image and installs dependencies).
**Subsequent runs take ~2-3 minutes** (provisioning only runs once).

### Running Specific Tests

You can run specific test suites instead of all tests:

```bash
# Run only integration tests
./tests/run-vm-tests.sh --integration

# Run only unit tests
./tests/run-vm-tests.sh --unit

# Run only e2e instrumentation tests
./tests/run-vm-tests.sh --e2e-inst

# Run only e2e network tests
./tests/run-vm-tests.sh --e2e-net

# Combine multiple test suites
./tests/run-vm-tests.sh --integration --e2e-inst
```

**Available test options:**
- `--unit` - Unit tests only (fastest)
- `--integration` - Integration tests only
- `--e2e-inst` - E2E instrumentation tests only
- `--e2e-net` - E2E network tests only

Multiple options can be combined. If no options are specified, all tests run.

## Customizing Resource Allocation

### Using Environment Variables

```bash
# Use 8 CPUs and 16GB RAM
VM_CPUS=8 VM_MEM=16 ./tests/run-vm-tests.sh

# Minimal resources (slower but less resource-intensive)
VM_CPUS=2 VM_MEM=4 ./tests/run-vm-tests.sh
```

### Using Command-Line Options

```bash
# Specify resources via flags
./tests/run-vm-tests.sh --vm-cpus 8 --vm-mem 16

# Keep VM running even after successful tests (for inspection)
./tests/run-vm-tests.sh --keep-vm

# Combine resource settings with test selection
./tests/run-vm-tests.sh --vm-cpus 8 --integration

# Run multiple test suites with custom resources
./tests/run-vm-tests.sh --vm-cpus 4 --vm-mem 8 --integration --e2e-inst
```

## Manual Testing Workflow

If you want more control over the test process:

### 1. Start the VM

```bash
cd /path/to/tracee

# Start test VM (lighter than dev VM, no K8s)
export VM_TYPE=test
vagrant up
```

**Note**: The first `vagrant up` takes longer as it:
- Downloads the Ubuntu 24.04 base image
- Provisions the VM with all dependencies
- Installs Go, Clang, Docker, and build tools

### 2. Access the VM

```bash
vagrant ssh
```

You'll be in the `/vagrant` directory, which is synced with your Tracee repository.

### 3. Build Tracee

```bash
# Inside the VM
cd /vagrant
make all
```

### 4. Run Tests Manually

```bash
# Run unit tests
make test-unit

# Run integration tests (requires root)
sudo make test-integration

# Run e2e instrumentation tests
sudo bash tests/e2e-inst-test.sh

# Run e2e network tests
sudo bash tests/e2e-net-test.sh
```

### 5. Exit and Destroy VM

```bash
# Exit the VM
exit

# Destroy the VM (frees disk space)
vagrant destroy -f
```

## Debugging Failed Tests

When tests fail, the VM is automatically preserved for debugging.

### Accessing the VM After Failure

```bash
cd /path/to/tracee
vagrant ssh
```

### Viewing Test Logs

Test logs are synced to your host machine:

```bash
# On your host (outside VM)
ls tests/vm-test-logs/

# View specific test logs
less tests/vm-test-logs/test-run-YYYYMMDD_HHMMSS.log
less tests/vm-test-logs/integration-tests-YYYYMMDD_HHMMSS.log
```

### Re-running Failed Tests

```bash
# Inside the VM
vagrant ssh

# Re-run all tests
sudo /vagrant/tests/run-tests-in-vm.sh

# Or run specific test suites
sudo make test-integration
sudo bash tests/e2e-inst-test.sh
```

### Cleaning Up After Debugging

```bash
# Exit the VM
exit

# Destroy the VM
vagrant destroy -f
```

## Understanding VM Types

The Tracee Vagrantfile supports two VM types:

### Test VM (`VM_TYPE=test`) - Recommended for Testing
- Lightweight configuration
- No Kubernetes (MicroK8s) installed
- Faster provisioning
- Designed for test execution

```bash
export VM_TYPE=test
vagrant up
```

### Dev VM (`VM_TYPE=dev`) - For Development
- Full development environment
- Includes MicroK8s, kubectl, helm
- Suitable for K8s-related development
- Takes longer to provision

```bash
export VM_TYPE=dev
vagrant up
```

**For running tests, always use `VM_TYPE=test`.**

## Troubleshooting

### VM Fails to Start

**Problem**: `vagrant up` fails with hypervisor errors

**Solution**:
1. Ensure VirtualBox or Parallels is installed
2. Check virtualization is enabled in BIOS/UEFI
3. Try destroying and recreating:
   ```bash
   vagrant destroy -f
   vagrant up
   ```

### Shared Folder Issues

**Problem**: `/vagrant` directory is empty or not mounted

**Solution**:
1. Ensure Guest Additions are installed (done automatically)
2. Try reloading the VM:
   ```bash
   vagrant reload
   ```

### Tests Fail with "Permission Denied"

**Problem**: Tests fail due to insufficient privileges

**Solution**:
- Always run tests with `sudo` inside the VM
- Use the automated script: `sudo /vagrant/tests/run-tests-in-vm.sh`

### VM is Slow or Unresponsive

**Problem**: VM performance is poor

**Solution**:
- Increase CPU/RAM allocation:
  ```bash
  VM_PROC=8 VM_MEM=16 vagrant up
  ```
- Close other resource-intensive applications
- Check host system has sufficient resources

### Docker Tests Fail

**Problem**: Container-related tests fail

**Solution**:
1. Ensure Docker is running in the VM:
   ```bash
   vagrant ssh
   sudo systemctl status docker
   sudo systemctl start docker
   ```

2. Pull required images manually:
   ```bash
   sudo docker pull busybox
   ```

### Out of Disk Space

**Problem**: VM or host runs out of disk space

**Solution**:
1. Clean up old VMs:
   ```bash
   vagrant global-status --prune
   vagrant destroy <vm-id>
   ```

2. Remove unused Vagrant boxes:
   ```bash
   vagrant box list
   vagrant box remove <box-name>
   ```

3. Force clean provisioning state (rarely needed):
   ```bash
   vagrant destroy -f
   vagrant up --provision
   ```

### Slow Provisioning / Dependencies Reinstalling

**Problem**: VM reinstalling Go, Clang, etc. on every boot

**Solution**:
```bash
# Provisioning should only run once. If it repeats:
vagrant destroy -f
vagrant up
```

After initial setup, `vagrant up` should start in ~30 seconds (not minutes).

## Advanced Usage

### Running Selective Tests

You can modify `tests/run-tests-in-vm.sh` or run specific make targets:

```bash
# Inside VM - run only integration tests
sudo make test-integration

# Run only e2e network tests
sudo bash tests/e2e-net-test.sh
```

### Preserving VM for Multiple Test Runs

```bash
# Start VM once
export VM_TYPE=test
vagrant up

# Run tests multiple times
vagrant ssh -c "sudo /vagrant/tests/run-tests-in-vm.sh"

# Make changes, re-run
vagrant ssh -c "sudo /vagrant/tests/run-tests-in-vm.sh"

# Destroy when done
vagrant destroy -f
```

### Using Different Kernel Versions

The Vagrantfile installs kernel `6.2.0-1018-aws` by default. To test with different kernels, modify the `KERNEL_VERSION` variable in the Vagrantfile provisioning section.

## Best Practices

1. **Always use VM for integration/e2e tests** - Never run these directly on your host
2. **Destroy VMs regularly** - Free up disk space: `vagrant destroy -f`
3. **Keep VM_TYPE=test for testing** - Faster and lighter than dev VM
4. **Check logs on failure** - Logs in `tests/vm-test-logs/` are your friend
5. **Allocate adequate resources** - At least 4 CPUs and 8GB RAM recommended

## CI/CD Integration

This VM testing approach mirrors what CI does, making it easier to debug CI failures locally:

```bash
# Reproduce CI test failures locally
./tests/run-vm-tests.sh

# Check the same logs CI would generate
cat tests/vm-test-logs/test-run-*.log
```

## Additional Resources

- [Vagrant Documentation](https://www.vagrantup.com/docs)
- [Tracee Building Guide](../docs/contributing/building/building.md)
- [Tracee Testing Guide](../.cursor/rules/testing-guide.mdc)
- [Setup Development Machine with Vagrant](../docs/contributing/setup-development-machine-with-vagrant.md)

## Summary

```bash
# Quick command reference

# Automated testing (recommended)
./tests/run-vm-tests.sh

# Custom resources
VM_PROC=8 VM_MEM=16 ./tests/run-vm-tests.sh

# Manual testing workflow
export VM_TYPE=test
vagrant up
vagrant ssh
sudo /vagrant/tests/run-tests-in-vm.sh
exit
vagrant destroy -f

# Debugging after failure
vagrant ssh
# ... debug ...
exit
vagrant destroy -f
```

Happy testing! 🧪


# Setup Development Machine with Vagrant

[HashiCorp Vagrant] leverages a declarative configuration file, which describes
all software requirements, packages, operating system configuration, and users
to provide the same development environment for everyone.

The [Vagrantfile](/Vagrantfile) describes the type of machine required to build Tracee from the [Getting Started](../index.md) guides.

This allows developers involved in the project to check out the code, run `vagrant up`, and be on their way.

## Prerequisites

- [Vagrant]
- [Hypervisor] supported by Vagrant, such as [VirtualBox] on a amd64 (Linux)
machine or [Parallels] on an arm64 M1 (Darwin) machine.

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

## Configure Resource Allocation (Optional)

Customize the VM's resources by setting the following environment variables:

- `VM_PROC`: Number of virtual processors. Defaults to half of the host's processors. Example:

  ```bash
  export VM_PROC=4
  ```

- `VM_MEM`: Memory in gigabytes. Defaults to 8GB. Example:

  ```bash
  export VM_MEM=16
  ```

## Start the VM

Run the following command to start the VM:

  ```bash
  vagrant up
  ```

Vagrant will download the base box, provision the VM, and install all required dependencies. This process may take some time.

## Accessing the VM

Once the VM is up and running, you can access it via SSH:

```bash
vagrant ssh
```

This will place you in the `/vagrant` directory inside the VM, which is synced with the Tracee directory on your host machine.

## Build and Run Tracee

You can now build Tracee within the VM using the provided Makefile. Consult the Tracee documentation for specific build instructions.
[Building Tracee Documentation](./building/building.md)

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

**Troubleshooting:**

- Shared Folder Issues: If you experience issues with the shared folder, ensure your virtualization software's Guest Additions are properly installed and that the shared folder settings in the Vagrantfile match your setup.

- Networking Issues: If you have trouble accessing forwarded ports, check your firewall settings on both the host and guest machines.

This setup provides a consistent and reproducible environment for developing and testing Tracee. Refer to the Tracee documentation for further details on building and using Tracee.

# Docker Quickstart

This section details how you can run Tracee through a container image.

## Prerequisites

Please ensure that Docker or another container runtime is working on your machine.

## Run the Tracee container images

All of the Tracee container images are stored in a public registry on [Docker Hub.](https://hub.docker.com/r/aquasec/tracee)
You can easily start experimenting with Tracee using the Docker image.

### On x86 architecture, please run the following command

```console
docker run \
  --name tracee --rm -it \
  --pid=host --cgroupns=host --privileged \
  -v /etc/os-release:/etc/os-release-host:ro \
  aquasec/tracee:latest
```

### Steps to run the Tracee container image on arm64

There are a few more steps involved in running Tracee through a container image on arm64 (M1).

Prerequisites:

* [Vagrant CLI](https://developer.hashicorp.com/vagrant/downloads) installed
* [Parallels Pro](https://www.parallels.com/uk/products/desktop/pro/) installed

First, clone the Tracee Git repository and move into the root directory:

```console
git clone git@github.com:aquasecurity/tracee.git

cd tracee
```

Next, use Vagrant to start a Parallels VM:

```console
vagrant up
```

This will use the [Vagrantfile](https://github.com/aquasecurity/tracee/blob/main/Vagrantfile) in the root of the Tracee directory.

Lastly, ssh into the created VM:

```console
vagrant ssh
```

Now, it is possible to run the Tracee Container image:

```console
docker run \
  --name tracee --rm -it \
  --pid=host --cgroupns=host --privileged \
  -v /etc/os-release:/etc/os-release-host:ro \
  aquasec/tracee:latest
```

To learn how to install Tracee in a production environment, [check out the Kubernetes guide](./kubernetes-quickstart).

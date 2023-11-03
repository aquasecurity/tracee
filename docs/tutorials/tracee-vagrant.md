# Using the Tracee container image on MacOS with Parallels and Vagrant

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

```shell
docker run --name tracee -it --rm \
  --pid=host --cgroupns=host --privileged \
  -v /etc/os-release:/etc/os-release-host:ro \
  -v /var/run:/var/run:ro \
  aquasec/tracee:latest
```

To learn how to install Tracee in a production environment, [check out the Kubernetes guide](./kubernetes-quickstart).

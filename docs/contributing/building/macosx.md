# Building Tracee in OSX

!!! Attention
    Building Tracee in an OSX environment is for development purposes only and
    **experimental** only.

## Requirements

* [Docker desktop](https://docs.docker.com/desktop/mac/install/)
* [brew](https://brew.sh)
* findutils (`brew install findutils`)
* make (`brew install make`)

## Creating a local building environment

Just like as described at [building environment](../building/environment.md),
under OSX you may create your local building environment by using the same
make targets:

```console
gmake -f builder/Makefile.tracee-make alpine-prepare
gmake -f builder/Makefile.tracee-make alpine-shell
```
    
```console
gmake -f builder/Makefile.tracee-make ubuntu-prepare
gmake -f builder/Makefile.tracee-make ubuntu-shell
```

## Executing tracee in the building environment

Tracee isn't meant to run in OSX but, with Docker, you can test building it.
If you try to run it from the build environment you may get the following error:

```console
sudo ./dist/tracee
```

```text
BPF: open /tmp/tracee/tracee.bpf.5_10_104-linuxkit.v0_8_0-rc-1-24-g72e0d02.o: no such file or directory
BPF: ATTENTION:
BPF: It seems tracee can't load CO-RE eBPF obj and could not find
BPF: the non CO-RE object in /tmp/tracee. You may build a non CO-RE eBPF
BPF: obj by using the source tree and executing "make install-bpf-nocore".
```

That happens because the virtual machine supporting docker desktop containers,
in OSX, does not have a kernel that supports eBPF CO-RE (it does not contain a
kernel with BTF information embedded on it).

In order for you to run tracee in OSX, it is recommended that you either use
[Vagrant](https://www.vagrantup.com) and the provided
[Vagrantfile](https://github.com/aquasecurity/tracee/blob/main/Vagrantfile), use
a virtual machine emulator (Parallels, VMware Fusion, ...) OR check the next
section about how to obtain docker kernel headers installed if you want a
"Docker only experience".

## Obtaining Docker Kernel Headers

Docker for Mac does not come with Kernel headers. You need to do the following
to execute non CO-RE Tracee:

1. Identify your docker version:

    ```console
    dockerver=$(docker version | grep  Version | head -n 1 | cut -d ':' -f 2 | xargs)
    ```

2. Run a container with Docker CLI, while mounting to the host path:

    ```console
    docker run -it -v /:/host \
        -v /var/run/docker.sock:/var/run/docker.sock \
        docker:$dockerver /bin/sh
    ```

3. Get the Kernel Header files from the linuxkit Docker image and copy it to the
   host /usr/src path:

    ```console
    mkdir /host/kheader
    cd /host/kheader
    linux_version="${VERSION:-$(uname -r | cut -d - -f 1)}"
    docker pull "linuxkit/kernel:$linux_version"
    docker save "linuxkit/kernel:$linux_version" > "linuxkit.tar"
    tar -xf "linuxkit.tar"
    layertar=$(find . -name layer.tar)
    tar -xf "$layertar"
    tar -xf "kernel-dev.tar" --directory /host/
    ```

4. You can now run Tracee on your Docker for Mac

## Apple Silicon

!!! Note
    Apple Silicon users might need to create their own virtual machine
    environment until Vagrant fully supports that architecture.

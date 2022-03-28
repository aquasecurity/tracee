# Setup Development Machine with Vagrant

[HashiCorp Vagrant] leverages a declarative configuration file, which describes all software requirements, packages,
operating system configuration, and users to provide the same development environment for everyone.

The [Vagrantfile] describes the type of machine required to build Tracee from source and follow the
[Getting Started](./../index.md) guides. This allows developers involved in the project to check out the code, run
`vagrant up`, and be on their way.

## Prerequisites

- [Vagrant](https://www.vagrantup.com/docs/installation)
- [Hypervisor](https://www.vagrantup.com/docs/providers) supported by Vagrant, such as [VirtualBox](https://www.virtualbox.org).

## Create Development Machine

Clone and change directory to Tracee Git repository:

```
git clone --branch {{ git.tag }} https://github.com/aquasecurity/tracee.git
cd tracee
```

Create and configure development machine according to the `Vagrantfile`:

```
vagrant up
```

If everything goes well, you can SSH into a running development machine and access its shell:

```console
$ vagrant ssh
Welcome to Ubuntu 21.10 (GNU/Linux 5.13.0-35-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Mar 26 18:08:08 UTC 2022

  System load:  0.94               Processes:                153
  Usage of /:   14.7% of 38.71GB   Users logged in:          1
  Memory usage: 59%                IPv4 address for docker0: 172.17.0.1
  Swap usage:   0%                 IPv4 address for enp0s3:  10.0.2.15


9 updates can be applied immediately.
9 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


Last login: Sat Mar 26 17:14:16 2022 from 10.0.2.2
vagrant@ubuntu-impish:~$
```

!!! tip
    Provisioning from scratch take time, but once created you can reuse the machine with `vagrant halt` and `vagrant up`
    commands. If something goes wrong with your machine, there's also the `vagrant destroy` to destroy it.

Synced folders enable Vagrant to sync a folder on the host machine to the development machine, allowing you to continue
working on your project's files on your host machine, but use the resources in the development machine to compile or run
Tracee.

By default, Vagrant will share Tracee project directory (the directory with the `Vagrantfile`) to `/vagrant`.
To get started, change directory to `/vagrant` and list files:

```
vagrant@ubuntu-impish:~$ cd /vagrant/
vagrant@ubuntu-impish:/vagrant$ ls -l
total 204
drwxr-xr-x 1 vagrant vagrant    224 Mar 17 14:31 3rdparty
-rw-r--r-- 1 vagrant vagrant   3474 Mar 17 14:31 CONTRIBUTING.md
-rw-r--r-- 1 vagrant vagrant  11358 Mar 17 14:31 LICENSE
-rw-r--r-- 1 vagrant vagrant  16529 Mar 25 07:46 Makefile
-rw-r--r-- 1 vagrant vagrant    133 Mar 17 14:31 NOTICE
-rw-r--r-- 1 vagrant vagrant   2116 Mar 26 16:41 RELEASING.md
-rw-r--r-- 1 vagrant vagrant   4097 Mar 17 14:31 Readme.md
-rw-r--r-- 1 vagrant vagrant   2732 Mar 26 16:41 Vagrantfile
drwxr-xr-x 1 vagrant vagrant    384 Mar 26 16:41 builder
drwxr-xr-x 1 vagrant vagrant    128 Dec 14 15:27 cmd
drwxr-xr-x 1 vagrant vagrant     96 Dec  8 14:20 deploy
drwxr-xr-x 1 vagrant vagrant    288 Mar 25 10:51 dist
drwxr-xr-x 1 vagrant vagrant    448 Mar 26 16:44 docs
-rw-r--r-- 1 vagrant vagrant    164 Mar 17 14:31 embedded-ebpf.go
-rw-r--r-- 1 vagrant vagrant    101 Mar 17 14:31 embedded.go
-rw-r--r-- 1 vagrant vagrant   4382 Mar 24 14:13 go.mod
-rw-r--r-- 1 vagrant vagrant 129439 Mar 24 14:13 go.sum
-rw-r--r-- 1 vagrant vagrant   1546 Mar 26 18:20 mkdocs.yml
drwxr-xr-x 1 vagrant vagrant    256 Mar 22 14:08 packaging
drwxr-xr-x 1 vagrant vagrant    416 Mar 24 14:13 pkg
drwxr-xr-x 1 vagrant vagrant    192 Dec 14 13:02 signatures
drwxr-xr-x 1 vagrant vagrant    160 Mar 24 14:13 tests
drwxr-xr-x 1 vagrant vagrant    224 Mar 24 11:59 types
```

As you can see the `/vagrant` directory contains source code of Tracee cloned from GitHub.

## Build and Run Tracee-eBPF and Tracee-Rules

To build `tracee-ebpf` and `tracee-rules` executable binaries, run the default Make target:

```
vagrant@ubuntu-impish:/vagrant$ make
```

Build targets are saved in the `/vagrant/dist` directory:

```
vagrant@ubuntu-impish:/vagrant$ ls -l dist/
total 47972
drwxr-xr-x 1 vagrant vagrant       96 Mar 25 10:45 btfhub
drwxr-xr-x 1 vagrant vagrant      224 Mar 25 10:45 libbpf
drwxr-xr-x 1 vagrant vagrant      512 Mar 25 10:46 rules
-rwxr-xr-x 1 vagrant vagrant 17876784 Mar 26 18:32 tracee-ebpf
-rwxr-xr-x 1 vagrant vagrant 26982352 Mar 25 10:45 tracee-rules
drwxr-xr-x 1 vagrant vagrant      544 Mar 26 18:31 tracee.bpf
-rw-r--r-- 1 vagrant vagrant  4232032 Mar 26 18:31 tracee.bpf.core.o
```

You can now run Tracee-eBPF and see raw events printed to the standard output in a tabular format:

```
vagrant@ubuntu-impish:/vagrant$ sudo ./dist/tracee-ebpf
TIME             UID    COMM             PID     TID     RET              EVENT                ARGS
18:39:43:781824  0      mkdocs           1       19      0                stat                 pathname: /docs/docs, statbuf: 0x7f851365eb20
18:39:43:782125  0      mkdocs           1       19      0                security_file_open   pathname: /docs/docs, flags: O_RDONLY|O_LARGEFILE|O_DIRECTORY, dev: 43, inode: 47, ctime: 1648313072000000000
18:39:43:782008  0      mkdocs           1       19      6                open                 pathname: /docs/docs, flags: O_RDONLY|O_LARGEFILE|O_DIRECTORY|O_CLOEXEC, mode: 0
18:39:43:783200  0      mkdocs           1       19      464              getdents64           fd: 6, dirp: 0x7f8513d8e0b8, count: 2048
18:39:43:783232  0      mkdocs           1       19      0                getdents64           fd: 6, dirp: 0x7f8513d8e0b8, count: 2048
18:39:43:783259  0      mkdocs           1       19      0                close                fd: 6
18:39:43:783271  0      mkdocs           1       19      0                stat                 pathname: /docs/docs/architecture.md, statbuf: 0x7f851365e9b0
18:39:43:783734  0      mkdocs           1       19      0                stat                 pathname: /docs/docs/install, statbuf: 0x7f851365e9b0
18:39:43:784163  0      mkdocs           1       19      0                stat                 pathname: /docs/docs/images, statbuf: 0x7f851365e9b0
18:39:43:784589  0      mkdocs           1       19      0                stat                 pathname: /docs/docs/integrations.md, statbuf: 0x7f851365e9b0
18:39:43:784906  0      mkdocs           1       19      0                stat                 pathname: /docs/docs/faq.md, statbuf: 0x7f851365e9b0
```

To analyze collected events and see detections printed to the standard output, run Tracee-eBPF and pipe it with Tracee-Rules:

```
vagrant@ubuntu-impish:/vagrant$ sudo ./dist/tracee-ebpf \
  --output=format:gob \
  --output=option:parse-arguments \
  | ./dist/tracee-rules \
  --input-tracee=file:stdin \
  --input-tracee=format:gob
Loaded 14 signature(s): [TRC-1 TRC-13 TRC-2 TRC-14 TRC-3 TRC-11 TRC-9 TRC-4 TRC-5 TRC-12 TRC-8 TRC-6 TRC-10 TRC-7]

*** Detection ***
Time: 2022-03-26T18:48:00Z
Signature ID: TRC-2
Signature: Anti-Debugging
Data: map[]
Command: strace
Hostname: ubuntu-impish
```

## Switch Between CO-RE and non CO-RE Linux Distribution

By default, the development machine is running Ubuntu Linux 21.10 Impish Indri. You can see that it has a BTF-enabled
kernel by checking the existence of the `/sys/kernel/btf/vmlinux` file.

```ruby
Vagrant.configure("2") do |config|
  # config.vm.box = "ubuntu/focal64"     # Ubuntu 20.04 Focal Fossa (non CO-RE)
  # config.vm.box = "ubuntu/hirsute64"   # Ubuntu 21.04 Hirsute Hippo (CO-RE)
  config.vm.box = "ubuntu/impish64"      # Ubuntu 21.10 Impish Indri (CO-RE)
end
```

Sometimes you may want to test Tracee with a non CO-RE distribution. You can do that by editing the Vagrantfile and
modifying the `config.vm.box` property. For example, you can switch to Ubuntu Linux 20.04 Focal Fossa as follows:

```ruby
Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/focal64"       # Ubuntu 20.04 Focal Fossa (non CO-RE)
  # config.vm.box = "ubuntu/hirsute64"   # Ubuntu 21.04 Hirsute Hippo (CO-RE)
  # config.vm.box = "ubuntu/impish64"    # Ubuntu 21.10 Impish Indri (CO-RE)
end
```

This change requires reprovisioning the development machine:

```
vagrant destroy
vagrant up
```

## Deploy Tracee on Kubernetes

The development machine described by Vagrantfile preinstalls [MicroK8s] Kubernetes cluster, which is suitable for testing
Tracee.

```
vagrant@ubuntu-impish:/vagrant$ microk8s status
microk8s is running
high-availability: no
  datastore master nodes: 127.0.0.1:19001
  datastore standby nodes: none
```

There's also the [kubectl] command installed to communicate with the cluster:

```
vagrant@ubuntu-impish:/vagrant$ kubectl get nodes -o wide
NAME            STATUS   ROLES    AGE    VERSION                    INTERNAL-IP   EXTERNAL-IP   OS-IMAGE       KERNEL-VERSION      CONTAINER-RUNTIME
ubuntu-impish   Ready    <none>   139m   v1.23.4-2+98fc2022f3ad3e   10.0.2.15     <none>        Ubuntu 21.10   5.13.0-35-generic   containerd://1.5.9
```

```
vagrant@ubuntu-impish:/vagrant$ kubectl create ns tracee-system
vagrant@ubuntu-impish:/vagrant$ kubectl apply -f deploy/kubernetes/tracee-postee/tracee.yaml -n tracee-system
daemonset.apps/tracee created
```

```
vagrant@ubuntu-impish:/vagrant$ kubectl logs -f daemonset/tracee -n tracee-system
INFO: probing tracee-ebpf capabilities...
INFO: starting tracee-ebpf...
INFO: starting tracee-rules...
Loaded 14 signature(s): [TRC-1 TRC-13 TRC-2 TRC-14 TRC-3 TRC-11 TRC-9 TRC-4 TRC-5 TRC-12 TRC-8 TRC-6 TRC-10 TRC-7]
Serving metrics endpoint at :3366
```

### Access Kubernetes Dashboard

Use the following command to get the token required to log in to the [Kubernetes Dashboard]:

```
kubectl -n kube-system describe secret \
  $(kubectl -n kube-system get secret | grep default-token | cut -d " " -f1)
```

Forward port 10443 in the development machine to the Kubernetes Dashboard's pod:

```
vagrant@ubuntu-impish:/vagrant$ kubectl port-forward --address 0.0.0.0 -n kube-system service/kubernetes-dashboard 10443:443
Forwarding from 0.0.0.0:10443 -> 8443
```

Since port 10443 is forwarded to port 10443 on your host, you can open your browser to
[https://localhost:10443](https://localhost:10443) and access Kubernetes Dashboard.

!!! warning
    Modern browser usually block insecure localhost TLS connections. For Google Chrome you may allow insecure TLS
    connections at [chrome://flags/#allow-insecure-localhost](chrome://flags/#allow-insecure-localhost).

## Preview Tracee Documentation

You can run [MkDocs] server and preview documentation on your host:

```
vagrant@ubuntu-impish:/vagrant$ make -f builder/Makefile.mkdocs
```

The development machine is running the MkDocs server listening on port 8000, which is forwarded to port 8000 on your
host. Therefore, you can open your browser to [http://localhost:8000](http://localhost:8000) and access documentation
pages.

[HashiCorp Vagrant]: https://www.vagrantup.com
[Vagrantfile]: https://github.com/aquasecurity/tracee/blob/{{ git.tag }}/Vagrantfile
[MicroK8s]: https://microk8s.io
[kubectl]: https://kubernetes.io/docs/tasks/tools/#kubectl
[Kubernetes Dashboard]: https://github.com/kubernetes/dashboard
[MkDocs]: https://www.mkdocs.org

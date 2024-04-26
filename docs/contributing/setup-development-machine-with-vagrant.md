# Setup Development Machine with Vagrant

[HashiCorp Vagrant] leverages a declarative configuration file, which describes
all software requirements, packages, operating system configuration, and users
to provide the same development environment for everyone.

The [Vagrantfile] describes the type of machine required to build Tracee from
source and follow the [Getting Started](../index.md) guides. This allows
developers involved in the project to check out the code, run `vagrant up`, and
be on their way.

## Prerequisites

- [Vagrant]
- [Hypervisor] supported by Vagrant, such as [VirtualBox] on a amd64 (Linux)
machine or [Parallels] on an arm64 M1 (Darwin) machine.


## Create Development Machine

Clone and change directory to Tracee Git repository:

```console
git clone --branch {{ git.tag }} https://github.com/aquasecurity/tracee.git
cd tracee
```

Create and configure development machine according to the `Vagrantfile`:

```console
vagrant up
```

If everything goes well, you can SSH into a running development machine and
access its shell:

```console
vagrant ssh
```

```text
vagrant@ubuntu-jammy:/vagrant$
```

!!! tip
    Provisioning from scratch take time, but once created you can reuse the
    machine with `vagrant halt` and `vagrant up` commands. If something goes
    wrong with your machine, there's also the `vagrant destroy` to destroy it
    and start over again.

Synced folders enable Vagrant to sync a folder on the host machine to the
development machine, allowing you to continue working on your project's files
on your host machine, but use the resources in the development machine to
compile or run Tracee.

By default, Vagrant will share Tracee project directory (the directory with the
`Vagrantfile`) to `/vagrant`. To get started list files:

```console
ls -l
```

```text
total 648
drwxr-xr-x 1 vagrant vagrant   4096 Mar 22 23:43 3rdparty
-rw-r--r-- 1 vagrant vagrant  11358 Mar 18 14:45 LICENSE
-rw-r--r-- 1 vagrant vagrant  21821 Mar 27 13:40 Makefile
-rw-r--r-- 1 vagrant vagrant    133 Mar 18 14:45 NOTICE
-rw-r--r-- 1 vagrant vagrant   2643 Mar 29 18:30 RELEASING.md
-rw-r--r-- 1 vagrant vagrant   2238 Mar 22 23:43 Readme.md
-rw-r--r-- 1 vagrant vagrant   3337 Mar 22 23:43 Vagrantfile
drwxr-xr-x 1 vagrant vagrant   4096 Mar 29 18:05 brand
drwxr-xr-x 1 vagrant vagrant   4096 Mar 22 23:43 builder
drwxr-xr-x 1 vagrant vagrant   4096 Mar 22 23:43 cmd
-rw-r--r-- 1 vagrant vagrant 415013 Mar 28 23:17 coverage.txt
drwxr-xr-x 1 vagrant vagrant   4096 Mar 18 14:45 deploy
drwxr-xr-x 1 vagrant vagrant   4096 Mar 29 18:15 dist
drwxr-xr-x 1 vagrant vagrant   4096 Mar 22 23:43 docs
-rw-r--r-- 1 vagrant vagrant    164 Mar 18 14:45 embedded-ebpf.go
-rw-r--r-- 1 vagrant vagrant    101 Mar 18 14:45 embedded.go
drwxr-xr-x 1 vagrant vagrant   4096 Mar 27 12:08 examples
-rw-r--r-- 1 vagrant vagrant   5599 Mar 29 17:22 go.mod
-rw-r--r-- 1 vagrant vagrant  77170 Mar 29 17:22 go.sum
-rw-r--r-- 1 vagrant vagrant  40206 Mar 22 23:43 mkdocs.yml
drwxr-xr-x 1 vagrant vagrant   4096 Mar 22 23:43 packaging
drwxr-xr-x 1 vagrant vagrant   4096 Mar 22 23:43 pkg
drwxr-xr-x 1 vagrant vagrant   4096 Mar 18 14:45 signatures
-rw-r--r-- 1 vagrant vagrant    157 Mar 22 23:43 staticcheck.conf
drwxr-xr-x 1 vagrant vagrant   4096 Mar 24 15:44 tests
drwxr-xr-x 1 vagrant vagrant   4096 Mar 22 23:43 types
```

As you can see the `/vagrant` directory contains source code of Tracee cloned
from GitHub.

## Build and Run Tracee

To build **tracee** executable binary, run the
default make target:

```console
make
```

Build targets are saved in the `/vagrant/dist` directory:

```console
ls -l dist/
```

```text
total 161096
drwxr-xr-x 1 vagrant vagrant     4096 Mar 29 19:06 btfhub
drwxr-xr-x 1 vagrant vagrant     4096 Mar 29 19:06 libbpf
drwxr-xr-x 1 vagrant vagrant     4096 Mar 29 19:08 signatures
-rwxr-xr-x 1 vagrant vagrant 62619312 Mar 29 19:08 tracee
-rw-r--r-- 1 vagrant vagrant 10753624 Mar 29 19:06 tracee.bpf.o
```

You can now run Tracee and see events printed to the standard output in a tabular format:

```console
sudo ./dist/tracee
```

```text
TIME             UID    COMM             PID     TID     RET              EVENT                     ARGS
19:10:09:453832  0      coredns          1       8       0                security_socket_connect   sockfd: 13, remote_addr: map[sa_family:AF_INET sin_addr:0.0.0.0 sin_port:8080]
19:10:09:454179  0      coredns          1       9       0                security_socket_accept    sockfd: 8, local_addr: map[sa_family:AF_INET6 sin6_addr::: sin6_flowinfo:0 sin6_port:8080 sin6_scopeid:0]
19:10:09:454265  0      coredns          1       9       0                security_socket_accept    sockfd: 8, local_addr: map[sa_family:AF_INET6 sin6_addr::: sin6_flowinfo:0 sin6_port:8080 sin6_scopeid:0]
19:10:09:454478  0      coredns          1       14      0                net_packet_http_request   metadata: {127.0.0.1 127.0.0.1 43306 8080 6 144 any}, http_request: &{GET HTTP/1.1 :8080 /health map[Accept-Encoding:[gzip] User-Agent:[Go-http-client/1.1]] 0}
19:10:09:454774  0      coredns          1       14      0                net_packet_http_response  metadata: {127.0.0.1 127.0.0.1 8080 43306 6 170 any}, http_response: &{200 OK 200 HTTP/1.1 map[Content-Length:[2] Content-Type:[text/plain; charset=utf-8] Date:[Wed, 29 Mar 2023 19:10:09 GMT]] 2}
19:10:10:452992  0      coredns          1       14      0                security_socket_connect   sockfd: 13, remote_addr: map[sa_family:AF_INET sin_addr:0.0.0.0 sin_port:8080]
19:10:10:453850  0      coredns          1       1       0                security_socket_accept    sockfd: 8, local_addr: map[sa_family:AF_INET6 sin6_addr::: sin6_flowinfo:0 sin6_port:8080 sin6_scopeid:0]
19:10:10:453983  0      coredns          1       1       0                security_socket_accept    sockfd: 8, local_addr: map[sa_family:AF_INET6 sin6_addr::: sin6_flowinfo:0 sin6_port:8080 sin6_scopeid:0]
19:10:10:454612  0      coredns          1       9       0                net_packet_http_request   metadata: {127.0.0.1 127.0.0.1 43318 8080 6 144 any}, http_request: &{GET HTTP/1.1 :8080 /health map[Accept-Encoding:[gzip] User-Agent:[Go-http-client/1.1]] 0}
19:10:10:455114  0      coredns          1       9       0                net_packet_http_response  metadata: {127.0.0.1 127.0.0.1 8080 43318 6 170 any}, http_response: &{200 OK 200 HTTP/1.1 map[Content-Length:[2] Content-Type:[text/plain; charset=utf-8] Date:[Wed, 29 Mar 2023 19:10:10 GMT]] 2}
```

## Switch Between CO-RE and non CO-RE Linux Distribution

By default, the development machine is running Ubuntu Linux 22.04 Jammy Jellyfish.
You can see that it has a BTF-enabled kernel by checking the existence of the
`/sys/kernel/btf/vmlinux` file.

```ruby
Vagrant.configure("2") do |config|
  # config.vm.box = "ubuntu/focal64"     # Ubuntu 20.04 Focal Fossa (non CO-RE)
  # config.vm.box = "ubuntu/hirsute64"   # Ubuntu 21.04 Hirsute Hippo (CO-RE)
  # config.vm.box = "ubuntu/impish64"    # Ubuntu 21.10 Impish Indri (CO-RE)
  config.vm.box = "ubuntu/jammy64"       # Ubuntu 22.04 Jammy Jellyfish (CO-RE)
...
```

Sometimes you may want to test Tracee with a non CO-RE distribution. You can do
that by editing the Vagrantfile and modifying the `config.vm.box` property. For
example, you can switch to Ubuntu Linux 20.04 Focal Fossa as follows:

```ruby
Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/focal64"       # Ubuntu 20.04 Focal Fossa (non CO-RE)
  # config.vm.box = "ubuntu/hirsute64"   # Ubuntu 21.04 Hirsute Hippo (CO-RE)
  # config.vm.box = "ubuntu/impish64"    # Ubuntu 21.10 Impish Indri (CO-RE)
  # config.vm.box = "ubuntu/jammy64"     # Ubuntu 22.04 Jammy Jellyfish (CO-RE)
...
```

This change requires re-provisioning the development machine:

```console
vagrant destroy
vagrant up
```

!!! Attention
    Ubuntu Focal distribution has introduced BTF information to their recent
    kernels, allowing eBPF CO-RE capable code to run. If you're willing to test
    non CO-RE kernels, make sure to use an older kernel that does not provide
    the `/sys/kernel/btf/vmlinux` file.

## Deploy Tracee with Postee on Kubernetes

The development machine described by Vagrantfile pre-installs [MicroK8s] Kubernetes cluster, which is suitable for testing Tracee.

```console
microk8s status
```

```text
microk8s is running
high-availability: no
  datastore master nodes: 127.0.0.1:19001
  datastore standby nodes: none
...
```

There's also the [kubectl] command installed and configured to communicate with
the cluster:

```console
kubectl get nodes -o wide
```

```
NAME           STATUS   ROLES    AGE   VERSION   INTERNAL-IP   EXTERNAL-IP   OS-IMAGE             KERNEL-VERSION      CONTAINER-RUNTIME
ubuntu-jammy   Ready    <none>   40m   v1.26.1   10.0.2.15     <none>        Ubuntu 22.04.2 LTS   5.15.0-69-generic   containerd://1.6.8
```

Create a new namespace called `tracee-system`:

```console
kubectl create ns tracee-system
```

Create Postee Persistent Volumes and StatefulSet in the `tracee-system`
namespace:

```console
kubectl apply -n tracee-system \
  -f https://raw.githubusercontent.com/aquasecurity/postee/v2.2.0/deploy/kubernetes/hostPath/postee-pv.yaml \
  -f https://raw.githubusercontent.com/aquasecurity/postee/v2.2.0/deploy/kubernetes/postee.yaml
```

Create Tracee DaemonSet in the `tracee-system`, configuring it to send 
detections to the standard output and send them over to Postee webhook on
http://postee-svc:8082:

```console
helm install tracee ./deploy/helm/tracee \
  --namespace tracee-system \
  --set hostPID=true \
  --set webhook=http://postee-svc:8082
```

!!! tip
    To test code that hasn't been released yet do the following:

    1. Build the `tracee:latest` container image from the current Git revision:
       ```console
       make -f builder/Makefile.tracee-container build-tracee
       ```
    2. Import the container image to MicroK8s registry:
       ```console
       docker image save -o /tmp/tracee-latest.tar tracee:latest
       microk8s ctr images import /tmp/tracee-latest.tar
       rm /tmp/tracee-latest.tar
       ```
    3. Create Tracee DaemonSet using `tracee:latest` as container image:
       ```console
       kubectl apply -n tracee-system -k deploy/kubernetes/tracee
       ```

While Tracee pod is running, run `strace ls` command and observe detection
printed to the standard output.

```console
kubectl logs -n tracee-system -f daemonset/tracee
```

```text
INFO: probing tracee capabilities...
INFO: starting tracee...
{"timestamp":1680119087787203746,"threadStartTime":1680119087787109775,"processorId":0,"processId":95599,"cgroupId":9789,"threadId":95599,"parentProcessId":95597,"hostProcessId":95599,"hostThreadId":95599,"hostParentProcessId":95597,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"strace","hostName":"ubuntu-jammy","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","podSandbox":false,"eventId":"6018","eventName":"Anti-Debugging detected","matchedScopes":1,"argsNum":0,"returnValue":0,"syscall":"","stackAddresses":null,"contextFlags":{"containerStarted":false,"isCompat":false},"args":[],"metadata":{"Version":"1","Description":"A process used anti-debugging techniques to block a debugger. Malware use anti-debugging to stay invisible and inhibit analysis of their behavior.","Tags":null,"Properties":{"Category":"defense-evasion","Kubernetes_Technique":"","Severity":1,"Technique":"Debugger Evasion","external_id":"T1622","id":"attack-pattern--e4dc8c01-417f-458d-9ee0-bb0617c1b391","signatureID":"TRC-102","signatureName":"Anti-Debugging detected"}}}
```

If everything is configured properly, you can find the same detection in Postee
logs:

```console
kubectl -n tracee-system logs -f postee-0
```

```text
2023/03/29 19:44:47 {"timestamp":1680119087787203746,"threadStartTime":1680119087787109775,"processorId":0,"processId":95599,"cgroupId":9789,"threadId":95599,"parentProcessId":95597,"hostProcessId":95599,"hostThreadId":95599,"hostParentProcessId":95597,"userId":1000,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"strace","hostName":"ubuntu-jammy","containerId":"","containerImage":"","containerName":"","podName":"","podNamespace":"","podUID":"","podSandbox":false,"eventId":"6018","eventName":"Anti-Debugging detected","matchedScopes":1,"argsNum":0,"returnValue":0,"syscall":"","stackAddresses":null,"contextFlags":{"containerStarted":false,"isCompat":false},"args":[],"metadata":{"Version":"1","Description":"A process used anti-debugging techniques to block a debugger. Malware use anti-debugging to stay invisible and inhibit analysis of their behavior.","Tags":null,"Properties":{"Category":"defense-evasion","Kubernetes_Technique":"","Severity":1,"Technique":"Debugger Evasion","external_id":"T1622","id":"attack-pattern--e4dc8c01-417f-458d-9ee0-bb0617c1b391","signatureID":"TRC-102","signatureName":"Anti-Debugging detected"}}}
```

### Access Kubernetes Dashboard

Use the following command to get the token required to log in to the
[Kubernetes Dashboard]:

```console
kubectl -n kube-system describe secret \
  $(kubectl -n kube-system get secret | grep default-token | cut -d " " -f1)
```

Forward port 10443 in the development machine to the Kubernetes Dashboard's
pod:

```console
kubectl port-forward --address 0.0.0.0 -n kube-system service/kubernetes-dashboard 10443:443
```

Since port 10443 is forwarded to port 10443 on your host, you can open your
browser to [https://localhost:10443](https://localhost:10443) and access
Kubernetes Dashboard.

!!! warning
    Modern browser usually block insecure localhost TLS connections. For Google
    Chrome you may allow insecure TLS connections at
    [chrome://flags/#allow-insecure-localhost](chrome://flags/#allow-insecure-localhost).

## Preview Tracee Documentation

You can run [MkDocs] server and preview documentation on your host:

```console
make -f builder/Makefile.mkdocs
```

The development machine is running the MkDocs server listening on port 8000,
which is forwarded to port 8000 on your host. Therefore, you can open your
browser to [http://localhost:8000](http://localhost:8000) and access
documentation pages.

[Vagrant]: https://www.vagrantup.com/docs/installation
[HashiCorp Vagrant]: https://www.vagrantup.com
[Vagrantfile]: https://github.com/aquasecurity/tracee/blob/{{ git.tag }}/Vagrantfile
[Hypervisor]: https://www.vagrantup.com/docs/providers
[VirtualBox]: https://www.virtualbox.org
[Parallels]: https://www.parallels.com
[MicroK8s]: https://microk8s.io
[MicroK8s add-ons]: https://microk8s.io/docs/addons
[kubectl]: https://kubernetes.io/docs/tasks/tools/#kubectl
[Kubernetes Dashboard]: https://github.com/kubernetes/dashboard
[Postee]: https://github.com/aquasecurity/postee
[Persistent Volumes]: https://kubernetes.io/docs/concepts/storage/persistent-volumes/
[MkDocs]: https://www.mkdocs.org

# Getting started with tracee in Kubernetes 

This guide is focused on running tracee on Kubernetes. To demonstrate how to use Tracee we will use minikube, a distribution of kubernetes that can run on your local machine. Alternatively, you could use most other Kubernetes clusters such as microk8s or from a cloud provider.

## Prerequisites 
 
minikube - see installation instructions and dependencies [here](https://minikube.sigs.k8s.io/docs/start/).

*Note: Your local cluster has to be run on an intel processor. Apple silicon is not currently supported.*
 
Start minikube and ensure that it is running correctly:

``` 
minikube start

```

```
kubectl get po -A

NAMESPACE     NAME                               READY   STATUS    RESTARTS   AGE 
kube-system   coredns-565d847f94-kd9xx           1/1     Running   0          15s 
kube-system   etcd-minikube                      1/1     Running   0          26s 
kube-system   kube-apiserver-minikube            1/1     Running   0          26s 
kube-system   kube-controller-manager-minikube   1/1     Running   0          26s 
kube-system   kube-proxy-cvqjm                   1/1     Running   0          15s 
kube-system   kube-scheduler-minikube            1/1     Running   0          26s 
kube-system   storage-provisioner                1/1     Running   0          15s 
```

## Running tracee as a daemon set

Tracee uses eBPF for host-based detections, meaning it has visibility into all processes running on a given host, regardless of them being separated into different containers or pods. Therefore, we want to have tracee running on each node.

Tracee can be installed through a Kubernetes [DaemonSet](https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/). This tells Kubernetes to have a single tracee process on each node.

You can find the full manifest on the [tracee repository](https://github.com/aquasecurity/tracee/blob/main/deploy/kubernetes/tracee/tracee.yaml).

We can install the DaemonSet directly from the Tracee repository through the following command:

```
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/tracee/{{ git.tag }}/deploy/kubernetes/tracee/tracee.yaml
```

You can verify that the tracee daemon set is running via:

``` 
kubectl get nodes 
NAME       STATUS   ROLES           AGE   VERSION 
minikube   Ready    control-plane   17m   v1.25.2 

kubectl get pods  
NAME           READY   STATUS    RESTARTS   AGE 
tracee-fcjmp   1/1     Running   0          4m11s 
```

You can see that we have a single pod running in our cluster, which has just a single node.  
 
## Tracee in action 

At this point tracee is running with default behaviour. You can see this at the top of the pod’s logs: 

``` 
kubectl logs tracee-fcjmp 

INFO: probing tracee-ebpf capabilities... 
INFO: starting tracee-ebpf... 
INFO: starting tracee-rules... 
Loaded 15 signature(s): [TRC-1 TRC-13 TRC-2 TRC-14 TRC-3 TRC-11 TRC-9 TRC-4 TRC-5 TRC-12 TRC-6 TRC-10 TRC-7 TRC-16 TRC-15]
``` 

Note that the pod-name has been taken from the previous command.

Each of the signatures listed above represent potentially malicious behaviors for tracee to detect and alert you on. You can see signature definitions [here](https://github.com/aquasecurity/tracee/tree/main/signatures). Tracee comes with these default signatures but also allows for you to write custom ones as well. More information can be found [here](../docs/detecting/rules.md)

Let’s trigger one of the default signatures to see tracee in action.

We can start by launching a shell on the same node as tracee, and install `strace`, a debugging tool that should trigger the TRC-2 signature which detects use of PTRACE, and should not be running in your kubernetes cluster.

```
kubectl create deployment nginx --image=nginx  # creates a deployment

kubectl exec -ti deployment/nginx -- bash  # get a bash into it

$~ apt update && apt install -y strace
$~ strace ls
...
```

Now to confirm that tracee caught this malicious behavior we can check the logs of the pod again:

```
kubectl logs tracee-fcjmp –follow

*** Detection ***
Time: 2022-10-20T17:08:13Z
Signature ID: TRC-2
Signature: Anti-Debugging
Data: map[]
Command: strace
Hostname: tracee-fcjmp
```

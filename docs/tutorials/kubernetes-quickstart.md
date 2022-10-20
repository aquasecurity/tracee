# Getting started with tracee in Kubernetes 

This guide is focused on running tracee on Kubernetes. To demonstrate how to use Tracee we will use minikube, a distribution of kubernetes that can run on your local machine. 
 

## Prerequisites 

 
minikube - see installation instructions and dependencies [here](https://minikube.sigs.k8s.io/docs/start/). 
 

Start minikube and ensure that it is running correctly:
 

``` 

minikube start 

``` 

```
[*] kubectl get po -A 

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

The following kubernetes manifest can be used to run tracee as a daemon set. This tells Kubernetes to have a single tracee process on each node. 

``` 

--- 
apiVersion: apps/v1 
kind: DaemonSet 
metadata: 
  labels: 
    app.kubernetes.io/name: tracee 
    app.kubernetes.io/component: tracee 
    app.kubernetes.io/part-of: tracee 
  name: tracee 
spec: 
  selector: 
    matchLabels: 
      app.kubernetes.io/name: tracee 
  template: 
    metadata: 
      labels: 
        app.kubernetes.io/name: tracee 
      name: tracee 
    spec: 
      containers: 
      - name: tracee 
        image: docker.io/aquasec/tracee:0.8.3 
        imagePullPolicy: IfNotPresent 
        env: 
          - name: LIBBPFGO_OSRELEASE_FILE 
            value: /etc/os-release-host 
        securityContext: 
          privileged: true 
        volumeMounts: 
        - name: tmp-tracee 
          mountPath: /tmp/tracee 
        - name: etc-os-release 
          mountPath: /etc/os-release-host 
          readOnly: true 
        # NOTE: Resource consumption will vary between different use cases and 
        # workload characteristics. User should monitor tracee for resource 
        # consumption before enabling resource limits. Capping tracee 
        # resources may cause loss of events and miss detections. 
        # resources: 
        #   limits: 
        #     cpu: "1" 
        #     memory: 1Gi # tracee has a 512MB in-memory events cache enabled by default 
        #   requests: 
        #     cpu: "1" 
        #     memory: 1Gi 
      tolerations: 
        - effect: NoSchedule 
          operator: Exists 
        - effect: NoExecute 
          operator: Exists 
      volumes: 
      - hostPath: 
          path: /tmp/tracee 
        name: tmp-tracee 
      - hostPath: 
          path: /etc/os-release 
        name: etc-os-release 
``` 
 

After saving the above manifest into a file called `tracee.yml` you can install it via: 

 

``` 
[*] kubectl apply –f tracee.yml 
``` 

 

You can verify that the tracee daemon set is running via: 

 

``` 
[*] kubectl get nodes 

NAME       STATUS   ROLES           AGE   VERSION 

minikube   Ready    control-plane   17m   v1.25.2 

  

[*] kubectl get pods  

NAME           READY   STATUS    RESTARTS   AGE 

tracee-fcjmp   1/1     Running   0          4m11s 
``` 

You can see that we have a single pod running in our cluster, which has just a single node.  

 
## Tracee in action 

At this point tracee is running with default behavior. You can see this at the top of the pod’s logs: 

``` 
[*] kubectl logs tracee-fcjmp 

INFO: probing tracee-ebpf capabilities... 

INFO: starting tracee-ebpf... 

INFO: starting tracee-rules... 

Loaded 15 signature(s): [TRC-1 TRC-13 TRC-2 TRC-14 TRC-3 TRC-11 TRC-9 TRC-4 TRC-5 TRC-12 TRC-6 TRC-10 TRC-7 TRC-16 TRC-15] 

``` 

Each of the signatures listed above represent potentially malicious behaviors for tracee to detect and alert you on. You can see signature definitions [here](https://github.com/aquasecurity/tracee/tree/main/signatures). Tracee comes with these default signatures but also allows for you to write custom ones as well. More information can be found [here](docs/detecting/rules.md) 

Let’s trigger one of the default signatures to see tracee in action. 
 
We can start by launching a shell in the tracee pod (and therefore on the same node), and install `strace`, a debugging tool that should trigger the TRC-2 signature which detects use of PTRACE, and should not be running in your kubernetes cluster. 


```
[*] kubectl exec --stdin --tty tracee-fcjmp – sh 

/tracee # apk add strace 
  OK: 14 MiB in 32 packages 

/tracee # strace ls 

... 
``` 

Now to confirm that tracee caught this malicious behavior we can check the logs of the pod: 

``` 
[*] kubectl logs tracee-fcjmp –follow 
 

*** Detection *** 

Time: 2022-10-20T17:08:13Z 

Signature ID: TRC-2 

Signature: Anti-Debugging 

Data: map[] 

Command: strace 

Hostname: tracee-fcjmp 

```

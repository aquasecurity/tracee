# Everything is an event

This guide will show an example of running the new Tracee experience we are experimenting with on Kubernetes.
For more context on this change, please check the discussion on [Github](https://github.com/aquasecurity/tracee/discussions/2499).

## Prerequisites

Helm - see installation instructions and dependencies [here](https://helm.sh/docs/intro/install/).
  
minikube - see installation instructions and dependencies [here](https://minikube.sigs.k8s.io/docs/start/).
 
*Note: Your local cluster must run on an Intel processor or ARM64. Apple silicon is not currently supported.*
  
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
 
## Running Tracee as a DaemonSet

Tracee is installed as a DaemonSet and the new experience we are trying is not enabled by default.
To install it we can use Helm and pass a custom flag `everythingIsAnEvent`.

First, add the Aqua Security Helm Repository to your Helm CLI:
```
helm repo add aqua https://aquasecurity.github.io/helm-charts/

helm repo update
```

Next, we can install the Helm Chart, with the new experience enabled, through the following command:
 
```
helm install tracee aqua/tracee  --namespace tracee-system --create-namespace  --set everythingIsAnEvent=true
``` 
 
You can verify that the Tracee DaemonSet is running via:
 
```
kubectl get pods
NAME           READY   STATUS    RESTARTS   AGE 
tracee-fcjmp   1/1     Running   0          4m11s
```

## Tracee in action
 
At this point Tracee is running with new behavior. You can see this at the top of the pod’s logs:
 
```
kubectl logs -f daemonset/tracee -n tracee-system
```

To test it we can trigger a rule, simulating a fileless attack. 
 
```
kubectl run tracee-tester --image=aquasec/tracee-tester -- TRC-105
```

It will print the rule as an event.
 
```
kubectl -n tracee-system logs -f ds/tracee | grep fileless_execution 

{"timestamp":1671119128028881186,"threadStartTime":883410317491,"processorId":1,"processId":9,"cgroupId":8972,"threadId":9,"parentProcessId":8,"hostProcessId":6136,"hostThreadId":6136,"hostParentProcessId":6135,"userId":0,"mountNamespace":4026532816,"pidNamespace":4026532817,"processName":"3","hostName":"tracee-tester","containerId":"c7e3c75bf167348bf79262bf6e688088f9b4d54ebcc79464f40b52b80c73ff55","containerImage":"docker.io/aquasec/tracee:latest","containerName":"tracee","podName":"tracee-wk8wh","podNamespace":"tracee-system","podUID":"5cb83966-e274-48f1-89fb-25bd748d2773","eventId":"6023","eventName":"fileless_execution","argsNum":15,"returnValue":0,"stackAddresses":null,"syscall":"execve",contextFlags":{"containerStarted":true,"isCompat":false},"args":[{"name":"cmdpath","type":"const char*","value":"/dev/fd/3"},{"name":"pathname","type":"const char*","value":"memfd:"},{"name":"dev","type":"dev_t","value":1},{"name":"inode","type":"unsigned long","value":1033},{"name":"ctime","type":"unsigned long","value":1671119128024105994},{"name":"inode_mode","type":"umode_t","value":33279},{"name":"interpreter_pathname","type":"const char*","value":"/lib/x86_64-linux-gnu/ld-2.28.so"},{"name":"interpreter_dev","type":"dev_t","value":234},{"name":"interpreter_inode","type":"unsigned long","value":1704546},{"name":"interpreter_ctime","type":"unsigned long","value":1671118551446622730},{"name":"argv","type":"const char**","value":[""]},{"name":"interp","type":"const char*","value":"/dev/fd/3"},{"name":"stdin_type","type":"string","value":"S_IFCHR"},{"name":"stdin_path","type":"char*","value":"/dev/null"},{"name":"invoked_from_kernel","type":"int","value":0}]}
```

Part of our goal with the new experience is to allow users to have the rules provide by tracee, but also be able to
collect events from the kernel they might be interested. Let's change the default events tracee was installed with,
by editing the tracee DamemonSet running on the cluster.

```
kubectl edit ds/tracee -n tracee-system
```

We can go to the line below, which shows all events (rules) Tracee has loaded, and add to it the `execve` syscall events.

From:

```
- event=anti_debugging,aslr_inspection,cgroup_notify_on_release,cgroup_release_agent,core_pattern_modification,default_loader_mod,disk_mount,docker_abuse,dynamic_code_loading,fileless_execution,hidden_file_created,illegitimate_shell,k8s_api_connection,k8s_cert_theft,kernel_module_loading,ld_preload,process_vm_write_inject,proc_fops_hooking,proc_kcore_read,proc_mem_access,proc_mem_code_injection,ptrace_code_injection,rcd_modification,sched_debug_recon,scheduled_task_mod,stdio_over_socket,sudoers_modification,syscall_hooking,system_request_key_mod
```

To (we added `execve` to the end of the list):
 
```
- event=anti_debugging,aslr_inspection,cgroup_notify_on_release,cgroup_release_agent,core_pattern_modification,default_loader_mod,disk_mount,docker_abuse,dynamic_code_loading,fileless_execution,hidden_file_created,illegitimate_shell,k8s_api_connection,k8s_cert_theft,kernel_module_loading,ld_preload,process_vm_write_inject,proc_fops_hooking,proc_kcore_read,proc_mem_access,proc_mem_code_injection,ptrace_code_injection,rcd_modification,sched_debug_recon,scheduled_task_mod,stdio_over_socket,sudoers_modification,syscall_hooking,system_request_key_mod,execve
``` 

Let's restart Tracee to run it with the new configuration.

```
kubectl rollout restart ds/tracee -n tracee-system
```

Now if you check the logs you will see the `execve` events that are happening on your cluster.

```
kubectl  logs -f ds/tracee -n tracee-system | grep execve

{"timestamp":1671119209363959531,"threadStartTime":964819225255,"processorId":1,"processId":6664,"cgroupId":4950,"threadId":6664,"parentProcessId":1428,"hostProcessId":6664,"hostThreadId":6664,"hostParentProcessId":1362,"userId":0,"mountNamespace":4026531841,"pidNamespace":4026531836,"processName":"kubelet","hostName":"pool-hst1l5k80-","containerId":"a54718a9bd3bd16ddcbebd1c1f058c8f9538a2526d25a048263b0c6e30776041","containerImage":"docker.io/aquasec/tracee:latest","containerName":"tracee","podName":"tracee-hr52p","podNamespace":"tracee-system","podUID":"82b23cd8-f81b-403d-92fb-85af412e5f73","eventId":"59","eventName":"execve","argsNum":2,"returnValue":0,"stackAddresses":null,"syscall":"execve",contextFlags":{"containerStarted":true,"isCompat":false},"args":[{"name":"pathname","type":"const char*","value":"/usr/bin/umount"},{"name":"argv","type":"const char*const*","value":["umount","/var/lib/kubelet/pods/b0067d27-41c6-46eb-bb53-c1e0c75af9b8/volumes/kubernetes.io~projected/kube-api-access-mgc48"]}]}
``` 

Tracee supports lots of events, you can see a list by running:

```
kubectl  exec ds/tracee -n tracee-system -- /tracee/tracee --list
```

Try them out and let us know what you think on the [Github](https://github.com/aquasecurity/tracee/discussions/2499) discussion or Slack.

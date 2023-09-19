# Working with Tracee Policies on Kubernetes


## Prerequisites

Before you begin, ensure that you have the following:

- A Kubernetes cluster up and running
- kubectl command-line tool installed and configured to work with your cluster
- Helm v3 or later installed on your local machine

## Install Tracee via Helm

To install Tracee using Helm, follow these steps:

Add the Aqua Security Helm repository:

```console
helm repo add aqua https://aquasecurity.github.io/helm-charts/
```

Install Tracee with the default settings:

```console
helm install tracee aqua/tracee \
    --namespace tracee-system --create-namespace \
    --set hostPID=true
```

This command installs Tracee in the tracee-system namespace, enabling the use of the host's PID namespace.

## Add a new Tracee policy

By default, Tracee comes with a policy for signature events. In this step, you will learn how to add a new policy suit your requirements.


The `tracee-policies` configmap should have all policies tracee will load when booting. Let's take a look on the default policy:

```console
kubectl get configmap -n tracee-system

NAME               DATA   AGE
tracee-config      1      58m
tracee-policies    2      58m
```

Let's take a look at a look at the default policy:

```console
kubectl describe configmap/tracee-policies -ntracee-system
```
```yaml
Name:         tracee-policies
Namespace:    tracee-system
Data
====
signatures.yaml:
----
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
	name: signature-events
	annotations:
		description: traces all signature events
spec:
	scope:
	  - global
	rules:
	  - event: stdio_over_socket
	  - event: k8s_api_connection
	  - event: aslr_inspection
	  - event: proc_mem_code_injection
	  - event: docker_abuse
	  - event: scheduled_task_mod
	  - event: ld_preload
	  - event: cgroup_notify_on_release
	  - event: default_loader_mod
	  - event: sudoers_modification
	  - event: sched_debug_recon
	  - event: system_request_key_mod
	  - event: cgroup_release_agent
	  - event: rcd_modification
	  - event: core_pattern_modification
	  - event: proc_kcore_read
	  - event: proc_mem_access
	  - event: hidden_file_created
	  - event: anti_debugging
	  - event: ptrace_code_injection
	  - event: process_vm_write_inject
	  - event: disk_mount
	  - event: dynamic_code_loading
	  - event: fileless_execution
	  - event: illegitimate_shell
	  - event: kernel_module_loading
	  - event: k8s_cert_theft
	  - event: proc_fops_hooking
	  - event: syscall_hooking
	  - event: dropped_executable
```

But let's supposed we also need tracee to trace all `execve` events, for it we need to change the configmap `tracee-policies` adding a new policy.

Let's edit the tracee-policies ConfigMap using kubectl:

```console
kubectl edit cm/tracee-policies -n tracee-system
```

The ConfigMap will open in your default text editor. Locate the data section.

To add a new policy for tracking execve events, add the following YAML block before the signatures.yaml section, maintaining proper indentation:

```yaml
data:
  events.yaml: |-
    apiVersion: tracee.aquasec.com/v1beta1
    kind: Policy
    metadata:
        name: execve-event
        annotations:
          description: traces all execve events
    spec:
        scope:
          - global
        rules:
          - event: execve
  signatures.yaml: |-
  ...
```
Save and close the file. The changes will be applied to the configmap.

!!! note
	If you having a problem editing the configmap, you can apply it directly with:
	```console
	kubectl apply -f https://gist.githubusercontent.com/josedonizetti/3df19a61d39840441ea5be448d6c9354/raw/c50b9b66d7996bb27b6fac301d24d6390e356f8c/tracee-policies-configmap.yaml
	```

Step 3: Restart Tracee Daemonset
After modifying the Tracee policies, you need to restart the Tracee daemonset for the changes to take effect.

Restart the Tracee daemonset using the following command:

```console
kubectl rollout restart ds/tracee -n tracee-system
```

Wait for the daemonset to restart and stabilize. You can monitor the progress using the following command:

```console
kubectl rollout status ds/tracee -n tracee-system
```

Then check for `execve` events:

```conosle
kubectl logs -f ds/tracee -n tracee-system | grep execve
```

```json
{"timestamp":1684688250477166817,"threadStartTime":1684688250477064221,"processorId":7,"processId":35694,"cgroupId":1386180,"threadId":35694,"parentProcessId":1033,"hostProcessId":3242201,"hostThreadId":3242201,"hostParentProcessId":3205483,"userId":0,"mountNamespace":4026532829,"pidNamespace":4026532833,"processName":"cri-dockerd","hostName":"minikube","container":{},"kubernetes":{},"eventId":"59","eventName":"execve","matchedPolicies":["execve_event"],"argsNum":2,"returnValue":0,"syscall":"execve","stackAddresses":null,"contextFlags":{"containerStarted":false,"isCompat":false},"args":[{"name":"pathname","type":"const char*","value":"/opt/cni/bin/bridge"},{"name":"argv","type":"const char*const*","value":["/opt/cni/bin/bridge"]},{"name":"envp","type":"const char*const*","value":null}]}
```

Once the daemonset is up and running, the modified policies will be applied.

Congratulations! You have successfully installed Tracee via Helm, modified the default policies to add an `execve` event policy.

Note: Modifying the policies may have security implications, so it is important to carefully consider the events you enable based on your specific requirements and security considerations.

Feel free to reach out if you have any further questions or need additional assistance!

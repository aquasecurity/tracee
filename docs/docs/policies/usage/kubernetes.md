# Kubernetes Policy Usage

## Custom Resource Definition

Tracee policies can be seamlessly integrated into Kubernetes using Custom Resource Definitions (CRDs). When Tracee is installed, the CRD is automatically applied, including a default policy. One can interact with Tracee policies as follows:

To view existing Tracee policies, use the following command:

```shell
kubectl get policies.tracee.aquasec.com
```

One can manage policies using standard kubectl commands. For example, to create, update, or delete a policy:

Create: Apply a new policy using the kubectl apply command.

```shell
kubectl apply -f your-policy.yaml
```

Update: Modify an existing policy using the kubectl edit command.

```shell
kubectl edit policies.tracee.aquasec.com <policy-name>
```

Delete: Remove a policy using the kubectl delete command.

```shell
kubectl delete policies.tracee.aquasec.com <policy-name>
```

## Operator

The Tracee Kubernetes Operator is a custom controller designed to manage Tracee policies as Custom Resource Definitions (CRDs) within a Kubernetes cluster. The Tracee Kubernetes Operator continually monitors changes to Tracee policies within the cluster. When a new policy is created, modified, or deleted, the operator automatically triggers a rolling restart of the Tracee DaemonSet. This ensures that Tracee is always running with the most up-to-date policies, providing enhanced security and compliance for your applications.

## Video Content 

 Tracking Kubernetes activity with eBPF and Tracee Policies 

 [![Watch the video](../../../images/traceepolicies.png)](https://youtu.be/VneWxs9Jpu0?si=eAnRDJVZShhg_td0)
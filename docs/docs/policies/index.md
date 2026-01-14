# Policies

Policies allow users to specify which [events](../events/index.md) to trace in which workloads. The policy `scope` defines which workloads this policy is limited to. The policy can define multiple `rules` that specify the events to trace. Policies are used both for the [Tracee CLI](./usage/cli.md) and for the [Tracee Kubernetes](./usage/kubernetes.md) installation. This makes it easier to share policies across use cases and environments.

It is possible to load up to 64 policies into Tracee.

## Policy Formats

Tracee supports two policy formats: **Kubernetes CRD format** and **Plain format** (YAML or JSON). Both formats are fully interchangeable and produce identical results. Tracee automatically detects the format when loading policies.

### Kubernetes CRD Format

The Kubernetes CRD format follows the standard Kubernetes Custom Resource Definition structure. Use this format for Kubernetes deployments or when managing policies as Kubernetes resources.

**Example:**

```yaml
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: overview-policy
  annotations:
    description: sample overview policy
spec:
  scope:
    - global
  rules:
    - event: dropped_executable
    - event: security_file_open
      filters:
        - data.pathname=/tmp/*
```

### Plain Format

The plain format provides a simpler, more concise syntax. Use this format for local development, testing, or non-Kubernetes environments.

**Example:**

```yaml
type: policy
name: overview-policy
description: sample overview policy
scope:
  - global
rules:
  - event: dropped_executable
  - event: security_file_open
    filters:
      - data.pathname=/tmp/*
```

Both formats support the same functionality. Tracee automatically detects the format by checking for `type: policy` (plain format) or `apiVersion` and `kind` fields (K8s CRD format). You can mix both formats in the same directory - Tracee will detect and load them correctly.

!!! Note
    Each event type can only be defined once in a policy

There are many ways to fine tune the scope and filters. For further information on the details, have a look at the respective sections: 

* [Specify the Policy scope](./scopes.md)
* [Filter events in the rules section](./rules.md)

While specifying event filters is optional, policies must have the `name`, `description`, `scope` and `rules` fields.

## Related Topics

* [Events Documentation](../events/index.md) - Learn about available events to use in policies
* [Policy Usage Guide](./usage/cli.md) - How to use policies with Tracee CLI
* [Kubernetes Policies](./usage/kubernetes.md) - How to deploy policies in Kubernetes
* [Troubleshooting](../troubleshooting.md) - Common policy-related issues and solutions

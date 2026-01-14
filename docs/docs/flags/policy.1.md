---
title: TRACEE-POLICY
section: 1
header: Tracee Policy Flag Manual
date: 2025/12
...

## NAME

tracee **\-\-policy** - Specify policy files or directories to load

## SYNOPSIS

tracee **\-\-policy** <file|dir> [**\-\-policy** <file|dir> ...]

## DESCRIPTION

The **\-\-policy** flag allows you to specify one or more policy files or directories containing policy files to load into Tracee.

Policies define which events to trace and how to filter them. When using the **\-\-policy** flag, you cannot use the **\-\-scope** or **\-\-events** flags together, as they serve different purposes for event selection.

Policy files are YAML files that follow the Tracee Policy API specification. Tracee supports two formats: **Kubernetes CRD format** and **Plain YAML format**. Both formats are fully interchangeable and Tracee automatically detects the format when loading policies. They define:

- **Scope**: Which workloads to trace (e.g., global, specific containers, processes)
- **Rules**: Which events to trace and optional filters to apply

When specifying a directory, Tracee will load all policy files found in that directory. When specifying individual files, you can use multiple **\-\-policy** flags to load multiple policies.

## EXAMPLES

- Load a single policy file:

  ```console
  --policy ./policy.yaml
  ```

- Load all policies from a directory:

  ```console
  --policy ./policies/
  ```

- Load multiple individual policy files:

  ```console
  --policy ./policy1.yaml --policy ./policy2.yaml
  ```

- Using the short form:

  ```console
  -p ./policy.yaml
  ```

- Complete example with policy:

  ```console
  tracee --policy ./security-policy.yaml --output json:events.json
  ```

## POLICY FILE FORMAT

Policy files use YAML format. Tracee supports two formats:

### Kubernetes CRD Format

```yaml
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: policy-name
  annotations:
    description: Policy description
spec:
  scope:
    - global
  rules:
    - event: event_name
      filters:
        - filter_expression
```

### Plain YAML Format

```yaml
type: policy
name: policy-name
description: Policy description
scope:
  - global
rules:
  - event: event_name
    filters:
      - filter_expression
```

Tracee automatically detects the format when loading policies. Both formats are fully interchangeable and produce identical results.

For more information about policy file formats and options, refer to the [Policy Documentation](../policies/index.md).

## NOTES

- If multiple policies are loaded, they are combined and all matching events from any policy will be traced
- Policy files must be valid YAML and conform to the Tracee Policy API specification


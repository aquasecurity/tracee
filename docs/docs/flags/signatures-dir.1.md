---
title: TRACEE-SIGNATURES-DIR
section: 1
header: Tracee Signatures Directory Flag Manual
date: 2025/12
...

## NAME

tracee **\-\-signatures-dir** - Specify directories to search for signature plugins

## SYNOPSIS

tracee **\-\-signatures-dir** <dir> [**\-\-signatures-dir** <dir> ...]

## DESCRIPTION

The **\-\-signatures-dir** flag allows you to specify one or more directories where Tracee should search for signature plugins in Go plugin (.so) format.

Signatures are security detection rules that can detect suspicious or malicious behavior patterns. They are compiled as Go plugins and loaded dynamically at runtime.

When Tracee starts, it searches for signature plugins in:

- The directories specified by **\-\-signatures-dir** flags, or
- Default signatures

Each signature plugin file must be a compiled Go plugin (.so file) that implements the Tracee signature interface. Loaded signatures create corresponding signature events that can be traced using policies or event flags.

## EXAMPLES

- Specify a single directory:

  ```console
  --signatures-dir /opt/tracee/signatures
  ```

- Specify multiple directories:

  ```console
  --signatures-dir /opt/tracee/signatures --signatures-dir /custom/signatures
  ```

- Use with policy to trace signature events:

  ```console
  tracee --signatures-dir /opt/tracee/signatures --policy ./security-policy.yaml
  ```

- List available signature events:

  ```console
  tracee --signatures-dir /opt/tracee/signatures list
  ```

## SIGNATURE PLUGINS

Signature plugins are compiled Go shared libraries (.so files) that implement the Tracee signature interface. Each plugin can define one or more signatures that detect specific security events or patterns.

When a signature plugin is loaded:

- The signatures it defines become available as traceable events
- These events can be referenced in policies or event flags
- Signature events are typically prefixed to distinguish them from system events

To create custom signatures, refer to the Tracee signature development documentation.

## NOTES

- Signature plugins must be compiled for the same architecture and Go version as Tracee
- Only valid Go plugin files (.so) will be loaded from the specified directories
- If no signatures are found, Tracee will continue to run but signature events will not be available
- The **\-\-signatures-dir** flag can be used with the **list** command to see available signature events before running Tracee


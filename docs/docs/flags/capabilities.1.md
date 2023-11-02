---
title: TRACEE-CAPABILITIES
section: 1
header: Tracee Capabilities Flag Manual
date: 2023/10
...

## NAME

tracee **\-\-capabilities** - Opt out from dropping capabilities by default or set specific ones

## SYNOPSIS

tracee **\-\-capabilities** [<bypass=[true|false]\> | <add=cap1(,cap2...)\> | <drop=cap1(,cap2...)\>] ... [**\-\-capabilities** [<add=cap1(,cap2...)\> | <drop=cap1(,cap2...)\>] ...]

## DESCRIPTION

The **\-\-capabilities** flag allows you to control the dropping of capabilities during execution time or set specific capabilities.

Possible options:

- **bypass=[true|false]**: Keep all capabilities during execution time. Setting **bypass=true** will opt out from dropping any capabilities.
- **add=cap1(,cap2...)**: Add specific capabilities to the "required" capabilities ring. You can provide multiple capability names separated by commas.
- **drop=cap1(,cap2...)**: Drop specific capabilities from the "required" capabilities ring. You can specify multiple capability names separated by commas.

Please note that the available capabilities will depend on the running system. For the list of capabilities available on your system, see the **list-caps** command.

## EXAMPLES

- To keep all capabilities during execution time, use the following flag:

  ```console
  --capabilities bypass=true
  ```

- To add specific capabilities (e.g., cap_kill and cap_syslog) to the "required" capabilities ring, use the following flag:

  ```console
  --capabilities add=cap_kill,cap_syslog
  ```

- To drop a specific capability (e.g., cap_chown) from the "required" capabilities ring, use the following flag:

  ```console
  --capabilities drop=cap_chown
  ```

Please refer to the [documentation](../advanced/dropping-capabilities.md) for more information on environment capabilities.

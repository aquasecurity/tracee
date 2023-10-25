
# LD_PRELOAD code injection detected

## Intro

The `LdPreload` signature identifies the use of `LD_PRELOAD` and
`LD_LIBRARY_PATH` environment variables, or alterations to the
`/etc/ld.so.preload` file, which can potentially be leveraged for code
injection. By preloading certain libraries, adversaries might gain the ability
to hijack function calls or manipulate program behavior.

## Description

This signature targets three main aspects:

1. Monitoring environment variables during process execution that are related to
library preloading.
2. Detecting when the `/etc/ld.so.preload` file is being opened with write
permissions.
3. Observing renaming operations that involve the `/etc/ld.so.preload` file.

These detections are pivotal, as the unauthorized or unintended use of
`LD_PRELOAD` can allow attackers to change the order in which a program loads
its libraries. This could enable them to inject malicious code or redirect
specific function calls to other unintended functions.

## Purpose

The primary goal of this signature is to detect and alert on potential code
injection attempts that exploit library preloading mechanisms. By detecting
alterations or suspicious usage of related environment variables or the preload
file, it aids in thwarting attempts by adversaries to subvert application
behavior or maintain a malicious foothold on the system.

## Metadata

- **ID**: TRC-107
- **Version**: 1
- **Name**: LD_PRELOAD code injection detected
- **EventName**: ld_preload
- **Description**: Monitors for the use of `LD_PRELOAD` or `LD_LIBRARY_PATH` environment variables and changes to the `/etc/ld.so.preload` file. These methods can be exploited for malicious code injection or altering program behavior.
- **Properties**:
  - **Severity**: 2
  - **Category**: persistence
  - **Technique**: Hijack Execution Flow
  - **Kubernetes_Technique**: N/A
  - **id**: attack-pattern--aedfca76-3b30-4866-b2aa-0f1d7fd1e4b6
  - **external_id**: T1574

## Findings

When any suspicious or predefined activities are detected, the signature
triggers a `Finding`, signaling a potential threat. This finding contains the
event's metadata and might also include data fields specifying the particular
environment variable that was used.

## Events Used

The signature listens to three event types:

1. `sched_process_exec` - Examines environment variables during process execution to detect the usage of `LD_PRELOAD` or `LD_LIBRARY_PATH`.
2. `security_file_open` - Monitors if the `/etc/ld.so.preload` file is being accessed with write permissions, indicating potential alterations.
3. `security_inode_rename` - Observes renaming operations involving the `/etc/ld.so.preload` file.

Using these events, the signature provides an extensive defense against
unauthorized or malicious utilization of library preloading mechanisms.

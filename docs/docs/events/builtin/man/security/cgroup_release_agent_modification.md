---
title: TRACEE-CGROUP-RELEASE-AGENT-MODIFICATION
section: 1
header: Tracee Event Manual
---

## NAME

**cgroup_release_agent** - detect modifications to cgroup release_agent file

## DESCRIPTION

This event detects modifications to the `release_agent` file within cgroups. The release agent is a critical component that specifies a script or command to be executed whenever a cgroup becomes empty. Due to its ability to execute arbitrary commands, unauthorized modifications to this file could indicate attempts at privilege escalation or container escape.

The event monitors both direct modifications and rename operations involving the release_agent file, helping detect various tampering techniques.

## SIGNATURE METADATA

- **ID**: TRC-1010
- **Version**: 1
- **Severity**: 3
- **Category**: privilege-escalation
- **Technique**: Escape to Host
- **MITRE ID**: attack-pattern--4a5b7ade-8bb5-4853-84ed-23f262002665
- **MITRE External ID**: T1611

## EVENT SETS

**signatures**, **default**

## DATA FIELDS

This signature event uses fields from the underlying security events:

**pathname** (*string*)
: Path to the release_agent file being accessed

**flags** (*string*)
: File access flags indicating the type of operation

**old_path** (*string*)
: Original path in case of rename operations

**new_path** (*string*)
: New path in case of rename operations

## DEPENDENCIES

- `security_file_open`: Monitor file access attempts
- `security_inode_rename`: Track file rename operations

## USE CASES

- **Container security**: Detect potential container escape attempts

- **Privilege escalation detection**: Monitor for unauthorized command execution setup

- **Runtime integrity**: Track changes to critical cgroup configurations

- **Incident response**: Identify tampering with container isolation mechanisms

## CGROUP SECURITY

Critical aspects of release_agent security:

- Executes with root privileges
- Runs outside container context
- Can access host system resources
- Triggered automatically on cgroup emptying

## ATTACK VECTORS

Common malicious uses include:

- **Command injection**: Inserting malicious commands
- **Container escape**: Breaking container isolation
- **Persistence**: Establishing automatic execution
- **Privilege escalation**: Gaining elevated access

## RISK ASSESSMENT

Risk factors to consider:

- **High Impact**: Can lead to container escape
- **Root Access**: Commands run with full privileges
- **Automated Execution**: Triggers without user interaction
- **Wide Access**: Can affect multiple containers

## RELATED EVENTS

- **cgroup_notify_on_release_modification**: Related cgroup control file changes
- **security_file_open**: File access monitoring
- **security_inode_rename**: File rename operations
- **container_create**: Container lifecycle events

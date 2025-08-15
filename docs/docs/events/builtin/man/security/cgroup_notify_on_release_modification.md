---
title: TRACEE-CGROUP-NOTIFY-ON-RELEASE-MODIFICATION
section: 1
header: Tracee Event Manual
---

## NAME

**cgroup_notify_on_release_modification** - detect modifications to cgroup notify_on_release file

## DESCRIPTION

This event detects modifications to the `notify_on_release` file within cgroups. The cgroups (Control Groups) feature in Linux manages resource allocation and isolation for process groups. The `notify_on_release` file controls whether notifications are sent when cgroup resources are released.

Unauthorized modifications to this file could indicate container escape attempts or privilege escalation attacks, as attackers might try to leverage cgroup release notifications for malicious purposes.

## SIGNATURE METADATA

- **ID**: TRC-106
- **Version**: 1
- **Severity**: 3
- **Category**: privilege-escalation
- **Technique**: Escape to Host
- **MITRE ID**: attack-pattern--4a5b7ade-8bb5-4853-84ed-23f262002665
- **MITRE External ID**: T1611

## EVENT SETS

**signatures**, **default**

## DATA FIELDS

This signature event has no specific data fields. It uses the fields from the underlying security_file_open event:

**pathname** (*string*)
: Path to the notify_on_release file being accessed

**flags** (*string*)
: File access flags indicating the type of operation

## DEPENDENCIES

- `security_file_open`: Monitor file access attempts in containers

## USE CASES

- **Container security**: Detect potential container escape attempts

- **Privilege escalation detection**: Identify unauthorized modifications to cgroup controls

- **Runtime integrity**: Monitor changes to container isolation boundaries

- **Compliance monitoring**: Track modifications to container security controls

## CONTAINER IMPLICATIONS

Modifications to notify_on_release can affect:

- Container isolation boundaries
- Resource cleanup notifications
- Container lifecycle events
- Process group management

## SECURITY IMPLICATIONS

Unauthorized modifications may enable:

- Container escape attempts
- Privilege escalation
- Resource exhaustion attacks
- Container isolation bypasses

## RISK ASSESSMENT

Risk factors to consider:

- **High Impact**: Can affect container isolation
- **Complex Detection**: Changes may appear legitimate
- **False Positives**: Legitimate container management tools may modify this file
- **Context Required**: Need to correlate with other container events

## RELATED EVENTS

- **cgroup_mkdir**: Cgroup creation events
- **cgroup_rmdir**: Cgroup removal events
- **security_file_open**: File access monitoring
- **container_create**: Container lifecycle events

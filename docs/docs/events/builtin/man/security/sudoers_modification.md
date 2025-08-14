---
title: TRACEE-SUDOERS-MODIFICATION
section: 1
header: Tracee Event Manual
---

## NAME

**sudoers_modification** - detect modifications to sudo configuration

## DESCRIPTION

This event detects modifications to the sudoers configuration files, which control sudo command privileges on Unix and Linux systems. The sudoers file (/etc/sudoers and files in /etc/sudoers.d/) defines which users can run what commands with elevated privileges, making it a critical security control point.

Unauthorized changes to these files could allow attackers to grant themselves or others elevated privileges, potentially leading to complete system compromise. The event monitors both direct modifications and rename operations involving sudoers files.

## SIGNATURE METADATA

- **ID**: TRC-1028
- **Version**: 1
- **Severity**: 2
- **Category**: privilege-escalation
- **Technique**: Sudo and Sudo Caching
- **MITRE ID**: attack-pattern--1365fe3b-0f50-455d-b4da-266ce31c23b0
- **MITRE External ID**: T1548.003

## EVENT SETS

**signatures**, **default**

## DATA FIELDS

This signature event uses fields from multiple underlying events:

**pathname** (*string*)
: Path to the sudoers file being accessed

**flags** (*string*)
: File access flags indicating modification

**old_path** (*string*)
: Original path in rename operations

**new_path** (*string*)
: New path in rename operations

## DEPENDENCIES

- `security_file_open`: Monitor file modifications
- `security_inode_rename`: Track file renames

## USE CASES

- **Privilege control**: Monitor sudo permission changes

- **System integrity**: Track critical file modifications

- **Security compliance**: Ensure proper sudo configuration

- **Incident response**: Detect unauthorized changes

## SUDOERS COMPONENTS

Critical files and locations:

- /etc/sudoers
- /etc/sudoers.d/
- visudo command
- sudoers.tmp
- User-specific sudo rules
- Host-specific rules
- Command aliases
- User aliases

## ATTACK VECTORS

Common malicious uses include:

- **Privilege escalation**: Grant unauthorized sudo access
- **Command execution**: Enable restricted commands
- **Persistence**: Maintain elevated access
- **Security bypass**: Disable security controls

## RISK ASSESSMENT

Risk factors to consider:

- **System-Wide Impact**: Affects all users
- **Root Access**: Controls superuser access
- **Security Control**: Core security mechanism
- **Configuration Impact**: Changes persist

## LEGITIMATE USES

Valid modification scenarios:

- User permission updates
- System administration
- Security policy changes
- Access control updates
- Command restrictions

## MITIGATION

Recommended security controls:

- Use visudo for changes
- Restrict sudoers.d/ access
- Monitor file integrity
- Regular audits
- Backup configurations

## RELATED EVENTS

- **security_file_open**: File access monitoring
- **security_inode_rename**: File rename operations
- **process_execute**: Command execution
- **scheduled_task_mod**: Task scheduling changes

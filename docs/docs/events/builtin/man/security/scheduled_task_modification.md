---
title: TRACEE-SCHEDULED-TASK-MODIFICATION
section: 1
header: Tracee Event Manual
---

## NAME

**scheduled_task_mod** - detect modifications to scheduled tasks

## DESCRIPTION

This event detects modifications to scheduled tasks and their configurations, particularly focusing on crontab and related files. Scheduled tasks are commonly used to execute commands at predefined times, making them attractive targets for attackers seeking to establish persistence or execute malicious code automatically.

The event monitors both direct file modifications and command executions related to task scheduling, providing comprehensive coverage of potential persistence mechanisms through scheduled tasks.

## SIGNATURE METADATA

- **ID**: TRC-1027
- **Version**: 1
- **Severity**: 2
- **Category**: persistence
- **Technique**: Cron
- **MITRE ID**: attack-pattern--2acf44aa-542f-4366-b4eb-55ef5747759c
- **MITRE External ID**: T1053.003

## EVENT SETS

**signatures**, **default**

## DATA FIELDS

This signature event uses fields from multiple underlying events:

**pathname** (*string*)
: Path to the scheduling configuration being accessed

**flags** (*string*)
: File access flags indicating modification

**old_path** (*string*)
: Original path in rename operations

**new_path** (*string*)
: New path in rename operations

**comm** (*string*)
: Command being executed (for scheduling tools)

## DEPENDENCIES

- `security_file_open`: Monitor file modifications
- `security_inode_rename`: Track file renames
- `sched_process_exec`: Monitor scheduling commands

## USE CASES

- **Persistence detection**: Identify unauthorized scheduling

- **Configuration control**: Track scheduling changes

- **System integrity**: Monitor task modifications

- **Compliance monitoring**: Track authorized changes

## SCHEDULING COMPONENTS

Critical files and commands:

- /etc/crontab
- /etc/cron.d/
- User crontabs
- Systemd timers
- at/batch jobs
- Anacron configurations
- Scheduling commands (crontab, at, batch)

## ATTACK VECTORS

Common malicious uses include:

- **Persistence**: Ensure malware survival
- **Privilege escalation**: Schedule privileged tasks
- **Command execution**: Run unauthorized code
- **Defense evasion**: Hide in legitimate jobs

## RISK ASSESSMENT

Risk factors to consider:

- **System-Wide Impact**: Affects all users
- **Privilege Level**: Often runs as root
- **Time-Based**: Delayed execution
- **Persistence**: Survives reboots

## LEGITIMATE USES

Valid modification scenarios:

- System maintenance
- Backup scheduling
- Update automation
- Log rotation
- Job scheduling

## MITIGATION

Recommended security controls:

- Access restrictions
- Change monitoring
- Audit logging
- Configuration control
- User permissions

## RELATED EVENTS

- **security_file_open**: File access monitoring
- **security_inode_rename**: File rename operations
- **sched_process_exec**: Command execution
- **rcd_modification**: Init script changes

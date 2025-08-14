---
title: TRACEE-RCD-MODIFICATION
section: 1
header: Tracee Event Manual
---

## NAME

**rcd_modification** - detect modifications to system runlevel scripts

## DESCRIPTION

This event detects modifications to runlevel control directories (rcd) scripts and related files. These scripts are executed during system boot and runlevel changes, making them attractive targets for attackers seeking to establish persistence. By modifying these initialization scripts, malicious actors can ensure their code runs automatically when the system starts or changes states.

The event monitors not only direct modifications to rcd files but also renames and executions of related commands like update-rc.d, providing comprehensive coverage of potential persistence mechanisms targeting system initialization.

## SIGNATURE METADATA

- **ID**: TRC-1026
- **Version**: 1
- **Severity**: 2
- **Category**: persistence
- **Technique**: RC Scripts
- **MITRE ID**: attack-pattern--dca670cf-eeec-438f-8185-fd959d9ef211
- **MITRE External ID**: T1037.004

## EVENT SETS

**signatures**, **default**

## DATA FIELDS

This signature event uses fields from multiple underlying events:

**pathname** (*string*)
: Path to the rcd file being accessed

**flags** (*string*)
: File access flags indicating modification

**old_path** (*string*)
: Original path in rename operations

**new_path** (*string*)
: New path in rename operations

**comm** (*string*)
: Command being executed (for update-rc.d)

## DEPENDENCIES

- `security_file_open`: Monitor file modifications
- `security_inode_rename`: Track file renames
- `sched_process_exec`: Monitor rc management commands

## USE CASES

- **Persistence detection**: Identify boot-time malware

- **System integrity**: Monitor init script changes

- **Configuration control**: Track service changes

- **Boot sequence protection**: Prevent unauthorized changes

## RUNLEVEL SCRIPTS

Critical script locations:

- /etc/rc.d/
- /etc/init.d/
- /etc/rc*.d/
- System V init scripts
- Update-rc.d command
- Chkconfig command

## ATTACK VECTORS

Common malicious uses include:

- **Boot persistence**: Ensure malware survival
- **Service creation**: Add malicious services
- **Privilege escalation**: Run as root at boot
- **Defense evasion**: Hide in legitimate scripts

## RISK ASSESSMENT

Risk factors to consider:

- **System-Wide Impact**: Affects all users
- **Root Access**: Runs with full privileges
- **Boot-Time Execution**: Early system access
- **Persistence**: Survives reboots

## LEGITIMATE USES

Valid modification scenarios:

- Service installation
- System configuration
- Package management
- Boot sequence optimization

## MITIGATION

Recommended security controls:

- File integrity monitoring
- Access restrictions
- Change management
- Audit logging
- Configuration control

## RELATED EVENTS

- **security_file_open**: File access monitoring
- **security_inode_rename**: File rename operations
- **sched_process_exec**: Command execution
- **scheduled_task_modification**: Task scheduling changes

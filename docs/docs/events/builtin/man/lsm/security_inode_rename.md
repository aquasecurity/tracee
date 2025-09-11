---
title: TRACEE-SECURITY-INODE-RENAME
section: 1
header: Tracee Event Manual
---

## NAME

**security_inode_rename** - LSM inode rename operation monitoring

## DESCRIPTION

Triggered when the Linux Security Module (LSM) framework performs security checks on inode rename operations. This event captures file and directory rename operations at the LSM level, providing detailed information about filesystem object renaming with complete path information.

File and directory renaming operations can have security implications, including attempts to hide files, evade detection, or bypass access controls, making LSM-level monitoring valuable for security analysis.

## EVENT SETS

**none**

## DATA FIELDS

**old_path** (*string*)
: The original path of the file or directory being renamed

**new_path** (*string*)
: The new path assigned to the file or directory

## DEPENDENCIES

**Kernel Probe:**

- security_inode_rename (required): LSM hook for inode rename security checks

## USE CASES

- **File security monitoring**: Track file and directory renaming for security analysis

- **Data protection**: Monitor file renaming that could indicate data hiding or theft

- **Compliance monitoring**: Ensure file operations follow security and compliance policies

- **Threat hunting**: Identify suspicious file renaming patterns indicating malicious activity

- **Forensic analysis**: Track file renaming operations for digital forensics and investigation

## RELATED EVENTS

- **task_rename**: Process renaming events
- **vfs_write**: File modification events that may accompany renaming
- **File operation events**: Related filesystem operation monitoring
- **Security file events**: Related file security monitoring

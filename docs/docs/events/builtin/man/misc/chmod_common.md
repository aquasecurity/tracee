---
title: TRACEE-CHMOD-COMMON
section: 1
header: Tracee Event Manual
---

## NAME

**chmod_common** - Event capturing changes to access permissions of files and directories

## DESCRIPTION

The **chmod_common** event captures any changes to file and directory access permissions, typically triggered by the `chmod`, `fchmod`, and `fchmodat` system calls. This event provides visibility into permission modifications that could be security-relevant.

## EVENT SETS

**none**

## DATA FIELDS

**pathname** (*string*)
: Path of the file or directory whose permissions are being changed

**mode** (*uint16*)
: The new mode (permission bits) being applied to the file or directory

## DEPENDENCIES

**Kernel Probe:**

- chmod_common (required): Kernel probe to catch access permission changes of files and directories

## USE CASES

- **Security Monitoring**: Track unauthorized permission changes that could indicate privilege escalation attempts

- **Compliance Auditing**: Monitor file permission changes for regulatory compliance requirements

- **System Administration**: Track configuration changes that modify file access controls

## RELATED EVENTS

- **chmod**: System call to change file permissions
- **fchmod**: System call to change permissions using file descriptor
- **fchmodat**: System call to change permissions relative to directory file descriptor
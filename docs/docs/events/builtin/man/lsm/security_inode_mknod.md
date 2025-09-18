---
title: TRACEE-SECURITY-INODE-MKNOD
section: 1
header: Tracee Event Manual
---

## NAME

**security_inode_mknod** - LSM inode creation operation monitoring

## DESCRIPTION

Triggered when the Linux Security Module (LSM) framework performs security checks on inode creation operations, specifically the mknod system call. The mknod operation creates filesystem nodes such as device files, named pipes (FIFOs), and other special files.

This event is important for security monitoring as creating device nodes or special files can be used for privilege escalation, creating covert communication channels, or bypassing security controls.

## EVENT SETS

**lsm_hooks**

## DATA FIELDS

**file_name** (*string*)
: The name/path of the file being created

**mode** (*uint16*)
: The file mode and type (permissions and file type)

**dev** (*uint32*)
: The device number (for device files)

## DEPENDENCIES

**Kernel Probe:**

- security_inode_mknod (required): LSM hook for inode creation security checks

## USE CASES

- **Device security monitoring**: Track creation of device files that could provide privileged access

- **Covert channel detection**: Monitor named pipe creation for unauthorized communication

- **Privilege escalation detection**: Identify attempts to create privileged device nodes

- **System integrity monitoring**: Track special file creation affecting system security

- **Compliance auditing**: Monitor special file creation for security compliance

## RELATED EVENTS

- **mknod, mknodat**: System calls for special file creation
- **security_inode_unlink**: Special file deletion monitoring
- **Device access events**: Device file usage monitoring
- **IPC events**: Inter-process communication monitoring

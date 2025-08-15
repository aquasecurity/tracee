---
title: TRACEE-SECURITY-SB-UMOUNT
section: 1
header: Tracee Event Manual
---

## NAME

**security_sb_umount** - security check for filesystem unmount operations

## DESCRIPTION

Triggered when a filesystem unmount operation is attempted in the system. This LSM (Linux Security Module) hook event captures the security check performed before a filesystem is unmounted, providing critical visibility into storage operations and system configuration changes.

The event provides detailed information about the unmount operation, including the device being unmounted, mount point, filesystem type, and unmount flags. This visibility is crucial for both system administration and security monitoring, as unexpected unmount operations could indicate security breaches or system instability.

This event is useful for:

- **Unmount monitoring**: Track filesystem unmount operations
- **Security auditing**: Detect unauthorized unmount attempts
- **System stability**: Monitor storage configuration changes
- **Resource management**: Track storage availability

## EVENT SETS

**none**

## DATA FIELDS

**dev_name** (*string*)
: The name of the device being unmounted

**path** (*string*)
: The filesystem path being unmounted

**type** (*string*)
: The filesystem type being unmounted (e.g., ext4, nfs)

**flags** (*uint32*)
: Unmount flags that specify unmount behavior

## DEPENDENCIES

**LSM Hook:**

- security_sb_umount (required): LSM hook for filesystem unmount security checks

## USE CASES

- **Security monitoring**: Detect unauthorized unmount operations

- **System administration**: Track filesystem unmount activities

- **Stability monitoring**: Verify proper storage detachment

- **Resource tracking**: Monitor storage availability changes

- **Threat detection**: Identify suspicious unmount operations

## UNMOUNT FLAGS

Common unmount flags to monitor:

- **MNT_FORCE**: Force unmount even if busy
- **MNT_DETACH**: Perform lazy unmount
- **MNT_EXPIRE**: Mark for expiry
- **UMOUNT_NOFOLLOW**: Don't follow symlinks
- **MNT_EXCL**: Only unmount if not shared

## FILESYSTEM TYPES

Common filesystem types affected:

- **Local filesystems**: ext4, xfs, btrfs
- **Network filesystems**: nfs, cifs, smbfs
- **Special filesystems**: tmpfs, devfs, procfs
- **Container filesystems**: overlayfs, aufs
- **Encrypted filesystems**: ecryptfs, encfs

## SECURITY IMPLICATIONS

Critical security aspects to monitor:

- **Data loss**: Through forced unmounts
- **Service disruption**: Through unexpected unmounts
- **Resource denial**: Through malicious unmounts
- **System instability**: Through improper unmounts
- **Container isolation**: Through shared mount unmounts

## RELATED EVENTS

- **umount**: Unmount system call events
- **umount2**: Extended unmount system call events
- **security_sb_mount**: Filesystem mount security events
- **security_sb_remount**: Filesystem remount security events

---
title: TRACEE-SECURITY-SB-MOUNT
section: 1
header: Tracee Event Manual
---

## NAME

**security_sb_mount** - security check for filesystem mount operations

## DESCRIPTION

Triggered when a filesystem mount operation is attempted in the system. This LSM (Linux Security Module) hook event captures the security check performed before a filesystem is mounted, providing critical visibility into storage operations and system configuration changes.

The event provides detailed information about the mount operation, including the device being mounted, mount point, filesystem type, and mount flags. This visibility is crucial for both system administration and security monitoring, as unexpected mount operations could indicate security breaches or misconfigurations.

## EVENT SETS

**none**

## DATA FIELDS

**dev_name** (*string*)
: The name of the device being mounted

**path** (*string*)
: The destination path where the device will be mounted

**type** (*string*)
: The filesystem type being mounted (e.g., ext4, nfs)

**flags** (*uint32*)
: Mount flags that specify mount options and behavior

## DEPENDENCIES

**LSM Hook:**

- security_sb_mount (required): LSM hook for filesystem mount security checks

## USE CASES

- **Security monitoring**: Detect unauthorized mount operations

- **System administration**: Track filesystem mount activities

- **Configuration auditing**: Verify storage setup changes

- **Compliance monitoring**: Ensure proper storage access controls

- **Threat detection**: Identify suspicious mount operations

## MOUNT FLAGS

Common mount flags to monitor:

- **MS_RDONLY**: Read-only mount
- **MS_NOSUID**: Ignore suid and sgid bits
- **MS_NODEV**: Prevent device-file access
- **MS_NOEXEC**: Prevent program execution
- **MS_SYNCHRONOUS**: Synchronous updates
- **MS_REMOUNT**: Remount existing mount
- **MS_BIND**: Bind mount
- **MS_SHARED**: Shared subtree
- **MS_PRIVATE**: Private subtree
- **MS_SLAVE**: Slave subtree
- **MS_UNBINDABLE**: Unbindable mount

## FILESYSTEM TYPES

Common filesystem types to monitor:

- **Local filesystems**: ext4, xfs, btrfs
- **Network filesystems**: nfs, cifs, smbfs
- **Special filesystems**: tmpfs, devfs, procfs
- **Container filesystems**: overlayfs, aufs
- **Encrypted filesystems**: ecryptfs, encfs

## SECURITY IMPLICATIONS

Critical security aspects to monitor:

- **Privilege escalation**: Through suid/dev files
- **Data exposure**: Through unexpected mounts
- **Container escapes**: Through host filesystem access
- **Persistence**: Through autostart locations
- **Resource abuse**: Through large filesystems

## RELATED EVENTS

- **mount**: Mount system call events
- **umount**: Unmount system call events
- **security_sb_umount**: Filesystem unmount security events
- **security_sb_remount**: Filesystem remount security events

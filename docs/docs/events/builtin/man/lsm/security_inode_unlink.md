---
title: TRACEE-SECURITY-INODE-UNLINK
section: 1
header: Tracee Event Manual
---

## NAME

**security_inode_unlink** - security check before unlinking an inode

## DESCRIPTION

Triggered when an inode is about to be unlinked, representing file or directory deletion operations. This LSM (Linux Security Module) hook event captures detailed information about the inode being unlinked, including its path, filesystem metadata, and timing information.

The event provides critical visibility into file deletion operations, which is essential for security monitoring, system auditing, and tracking changes to sensitive files or directories. It captures the state of the file or directory before it is removed from the filesystem.

## EVENT SETS

**none**

## DATA FIELDS

**pathname** (*string*)
: The path to the file or directory being unlinked

**inode** (*uint64*)
: Inode number of the file or directory

**dev** (*uint32*)
: Device number associated with the inode

**ctime** (*uint64*)
: Creation time of the file or directory

## DEPENDENCIES

**LSM Hook:**

- security_inode_unlink (required): LSM hook for inode unlink operations

## USE CASES

- **Security monitoring**: Track deletion of sensitive files and directories

- **Audit compliance**: Monitor file removal for regulatory compliance

- **Incident response**: Investigate unauthorized file deletion activities

- **System integrity**: Detect tampering with critical system files

- **Forensic analysis**: Track file deletion patterns during investigations

## PERFORMANCE CONSIDERATIONS

The event captures details on each unlinked inode, which may introduce overhead:

- **High-frequency operations**: Impact in environments with frequent file creation/deletion
- **Directory monitoring**: Additional overhead when monitoring large directories
- **Cache pressure**: Potential memory pressure from tracking many operations
- **System load**: Consider monitoring scope in high-throughput environments

## FILESYSTEM OPERATIONS

The event captures various unlink scenarios:

- **File deletion**: Regular file removal operations
- **Directory removal**: Empty directory deletion
- **Hard link removal**: Unlinking one of multiple hard links
- **Temporary file cleanup**: Removal of temporary files
- **Application uninstallation**: Bulk file removal operations

## SECURITY IMPLICATIONS

Critical security aspects to monitor:

- **Sensitive file deletion**: Unauthorized removal of important files
- **System file tampering**: Modification of critical system files
- **Malware cleanup**: Detection of malware self-removal
- **Data destruction**: Monitoring for mass file deletion events

## RELATED EVENTS

- **security_inode_mknod**: Inode creation events
- **security_inode_symlink**: Symbolic link creation events
- **security_inode_rename**: File/directory rename operations
- **unlink**: Unlink system call events
- **unlinkat**: Unlink-at system call events

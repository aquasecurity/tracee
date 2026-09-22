---
title: TRACEE-FILE-OPEN-MOUNT-WRITE-DENIED
section: 1
header: Tracee Event Manual
---

## NAME

**file_open_mount_write_denied** - a file open that requested mount write access was denied because the mount or filesystem was read-only

## DESCRIPTION

Triggered when a VFS read-only permission check returns `EROFS` during a write-like file open and the final open returns the same error. Per-mount denials are observed at the mount-write access helper. Filesystem-wide denials that occur earlier are observed at `inode_permission`. The pathname is the immutable kernel copy used for path lookup, rather than a userspace pointer captured at syscall entry.

The event covers ordinary write opens as well as creation and truncation attempts. Per-mount and filesystem-wide read-only state are reported separately.

The pathname preserves the exact kernel-owned input spelling but is not a canonical resolved path. Relative paths must be interpreted with `dirfd` and event process context. Symlink and rename resolution is left to the VFS. Only open-time mount-write permission decisions are reported; writes through file descriptors opened before a filesystem becomes read-only are outside this event's scope.

The classification fields are snapshots taken after the permission helper returns. During a concurrent read-only remount transition, both fields can be false even though the helper returned `EROFS`. The `inode_permission` fallback classifies an `EROFS` return on the filesystem permission path; a custom filesystem or LSM that deliberately returns the same error is indistinguishable at this probe boundary. Tracking is bounded to four nested opens per thread, and deeper nesting is skipped until the stack unwinds.

## EVENT SETS

**fs**, **fs_file_ops**

## DATA FIELDS

**dirfd** (*int32*)
: Directory file descriptor used to resolve a relative pathname

**pathname** (*string*)
: Kernel-owned input pathname used for the open attempt

**flags** (*int32*)
: Open flags used for the attempt

**mount_read_only** (*bool*)
: Whether the selected mount had the per-mount `MNT_READONLY` flag when write access was denied

**filesystem_read_only** (*bool*)
: Whether the filesystem permission path denied the open as read-only, or the mount-write check observed `SB_RDONLY`

**returnValue** (*int64*)
: Final open return value; this event is emitted only for `-EROFS`

## DEPENDENCIES

**Kernel Probe:**

- do_file_open or do_filp_open (kprobe + kretprobe, required): Correlates the immutable pathname with the final open result
- mnt_get_write_access or __mnt_want_write (kprobe + kretprobe, required): Confirms the mount-write permission decision and records the selected mount
- inode_permission (kretprobe, required): Captures filesystem-wide read-only denials that occur before mount write access is requested

## USE CASES

- **Tamper monitoring**: Detect attempts to modify files protected by read-only mounts

- **Container monitoring**: Observe writes denied by read-only bind mounts in container mount namespaces

- **Configuration validation**: Verify that read-only mount controls reject creation and truncation attempts

- **Incident investigation**: Distinguish mount read-only denials from DAC, ACL, or LSM permission failures

## RELATED EVENTS

- **security_file_open**: LSM hook reached only after mount write access succeeds
- **openat**: Open syscall event with the original userspace arguments
- **file_modification**: Successful file modifications observed after open
- **vfs_write**: VFS write operations on already opened files

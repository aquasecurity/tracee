---
title: TRACEE-SECURITY-PATH-NOTIFY
section: 1
header: Tracee Event Manual
---

## NAME

**security_path_notify** - security check for filesystem notification registration

## DESCRIPTION

Triggered when a process attempts to register a filesystem notification through any of the filesystem notification APIs (dnotify, inotify, or fanotify). This LSM (Linux Security Module) hook event captures the security check performed when setting up filesystem watches.

The event provides detailed information about the filesystem object being watched and the types of events being monitored. This is particularly important for security monitoring as filesystem notifications can be used for both legitimate monitoring and potential malicious activities.

This event is useful for:

- **Filesystem monitoring**: Track who's watching filesystem changes
- **Security auditing**: Monitor filesystem notification setup
- **Access control**: Verify notification registration permissions
- **Behavior analysis**: Understand application monitoring patterns

## EVENT SETS

**none**

## DATA FIELDS

**pathname** (*string*)
: Filesystem path for which the watch is being registered

**inode** (*uint64*)
: Inode number of the filesystem object

**dev** (*uint32*)
: Device identifier of the filesystem object

**mask** (*uint64*)
: Mask representing the filesystem events to monitor

**obj_type** (*uint32*)
: The type of filesystem object to be watched

## DEPENDENCIES

**LSM Hook:**

- security_path_notify (required): LSM hook for filesystem notification security checks

## USE CASES

- **Security monitoring**: Track filesystem watch registration attempts

- **Access control**: Verify notification registration permissions

- **Behavior analysis**: Understand application monitoring patterns

- **Audit compliance**: Track filesystem monitoring activities

- **Threat detection**: Identify suspicious monitoring behavior

## NOTIFICATION APIS

The event captures notifications from multiple APIs:

- **dnotify**: Directory notification (legacy)
- **inotify**: File and directory monitoring
- **fanotify**: Advanced filesystem monitoring and access control

## WATCH MASKS

Common notification mask combinations:

- **IN_ACCESS**: File access
- **IN_MODIFY**: File modification
- **IN_ATTRIB**: Metadata changes
- **IN_CLOSE**: File close operations
- **IN_OPEN**: File open operations
- **IN_MOVED**: File move operations
- **IN_CREATE**: File/directory creation
- **IN_DELETE**: File/directory deletion

## SECURITY IMPLICATIONS

Important security considerations:

- **Information disclosure**: Monitoring sensitive files
- **Resource exhaustion**: Excessive watch registrations
- **Privilege escalation**: Unauthorized monitoring
- **Side-channel attacks**: Information leakage through notifications
- **Denial of service**: Watch limit exhaustion

## PERFORMANCE CONSIDERATIONS

Watch registration impact:

- **Watch limits**: System-wide and per-process limits
- **Memory usage**: Each watch consumes kernel resources
- **Notification overhead**: Event generation and delivery cost
- **Filesystem impact**: Additional metadata tracking

## RELATED EVENTS

- **inotify_add_watch**: inotify watch registration
- **fanotify_mark**: fanotify mark operations
- **security_file_open**: File open security events
- **security_inode_unlink**: File deletion security events

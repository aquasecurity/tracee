# file_deletion

## Intro
file_deletion - a file was deleted.

## Description
A file was deleted.
This event enables monitoring of file deletions.
This event is intended for users to gain insight into the machines' runtime operations.

## Arguments
* `absolute_path`:`const char*`[K] - The file resolved absolute path.
* `last_changed`:`unsigned long`[K] - The file last modification time in epoch.

### Available Tags
* K - Originated from kernel-space.
* U - Originated from user space (for example, pointer to user space memory used to get it)
* TOCTOU - Vulnerable to TOCTOU (time of check, time of use)
* OPT - Optional argument - might not always be available

## Hooks
### security_inode_unlink
#### Type
kprobe.
#### Purpose
Indicates a inode unlinked, meaning a file was deleted.

## Example Use Case
Can be used to monitor file life cycle on the system.

## Issues


## Related Events
security_inode_unlink
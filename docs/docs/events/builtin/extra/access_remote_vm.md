# access_remote_vm

## Intro
access_remote_vm - gain access to the virtual memory of a separate process through the use of the procfs mem file.

## Description
This event marks access attempt of a process to the virtual memory of another process using the procfs mem file associated with that specific process (/proc/<pid>/mem).
It is a more elaborated event than the `security_file_open` of the mem file.

## Arguments
* `remote_pid`: `int`[K] - PID of the process the memory area belongs to.
* `start_address`: `void *`[K] - Start address of the operation.
* `gup_flags`: `unsigned int`[K] - Flags for get_user_pages operation.
* `vm_flags`: `unsigned long`[K] - Virtual memory flags.
* `mapped.path`: `const char*`[K] - Path of the mapped file, or the name of memory area if no file is mapped.
* `mapped.device_id`: `dev_t`[K,OPT] - Device ID of the mapped file.
* `mapped.inode_number`: `unsigned long`[K,OPT] - Inode number of the mapped file.
* `mapped.ctime`: `unsigned long`[K,OPT] - Creation time of the mapped file.

## Hooks
### get_user_pages_remote
#### Type
kprobe + kretprobe
#### Purpose
The main function that implements the access to the virtual memory area of the other process.

### generic_access_phys
#### Type
kprobe
#### Purpose
A fallback function, implementing the `access` method of the `vma_operations` struct for most of the vmas. It is used to access special memory areas.

## Related Events
`security_file_open`,`security_mmap_file`,`vfs_write`,`vfs_writev`,`vfs_read`,`vfs_readv`
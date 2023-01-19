# vfs_read

## Intro
vfs_read - generic FS file read to a buffer

## Description
An event indicating that a read from a file to a buffer was done.
The event is not FS specific, and the hook is on the inner implementation of the `read` and other buffer read syscalls.
Notice that there are more methods for file reading other than this, like `vfs_readv`, file mapping, etc.

## Arguments
* `pathname`:`const char*`[K] - the path of the file read
* `dev`:`dev_t`[K] - the device the file resides in
* `inode`:`unsigned long`[K] - the inode of the file in the device
* `count`:`size_t`[K] - the size requested to be read by this operation
* `pos`:`off_t`[K] - the start position for the read

## Hooks
### vfs_read
#### Type
kprobe + kretprobe
#### Purpose
The implementation of the `read`, `readv` syscall after fd resolving.

## Related Events
`read`,`vfs_readv`,`vfs_write`
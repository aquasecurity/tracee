# vfs_readv

## Intro
vfs_readv - generic FS file read to a vector

## Description
An event indicating that a read from a file to a vector was done.
The event is not FS specific, and the hook is on the inner implementation of the `readv` and other vector read syscalls.
Notice that there are more methods for file reading other than this, like `vfs_read`, file mapping, etc.

## Arguments
* `pathname`:`const char*`[K] - the path of the file read
* `dev`:`dev_t`[K] - the device the file resides in
* `inode`:`unsigned long`[K] - the inode of the file in the device
* `vlen`:`unsigned long`[K] - the amount of buffers requested to be read by this operation to the vector
* `pos`:`off_t`[K] - the start position for the read

## Hooks
### vfs_readv
#### Type
kprobe + kretprobe
#### Purpose
The implementation of the `readv`, `preadv` and `preadv2` syscall after fd resolving.

## Related Events
`readv`,`vfs_read`,`vfs_writev`
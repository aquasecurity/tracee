# magic_write

## Intro
magic_write - write operation to a file which changed the file's headers

## Description
An event marking that a new file is written, or an existing file header changed.
The event occurs whenever a write operation to a file in offset 0 is done.
The purpose of the event is to give the user information about the file's
type and other meta-data needed to understand if the file is a threat.

### Note
The event doesn't occur for FIFO files or other files with no persistent offsets,
to reduce spam events.

## Arguments
* `pathname`:`const char*`[K] - the path of the file written.
* `bytes`:`bytes`[U,TOCTOU] - the first 20 bytes of the file.
* `dev`:`dev_t`[K] - the device the file resides in.
* `inode`:`unsigned long`[K] - the inode of the file in the FS.

## Hooks
### vfs_write
#### Type
kprobe + kretprobe
#### Purpose
Catch write operations to a file using the `write` syscall

### vfs_writev
#### Type
kprobe + kretprobe
#### Purpose
Catch write operations to a file using the `writev` syscall

### __kernel_write
#### Type
kprobe + kretprobe
#### Purpose
Catch write operations to a file from within the kernel (written buffer resides in kernel space)

## Example Use Case

## Issues

## Related Events
write, writev, vfs_write, vfs_writev, __kernel_write, security_file_open
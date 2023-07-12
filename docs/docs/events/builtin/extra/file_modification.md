# file_modification

## Intro
file_modification - a file was changed by a process

## Description
An event marking that a file was modified. This event is only submitted once between the open and close of the file by a process.

## Arguments
* `file_path`:`const char*`[K] - the path of the file that was changed.
* `dev`:`dev_t`[K] - the device of which this file belongs to.
* `inode`:`unsigned long`[K] - the inode number of this file.
* `old_ctime`:`unsigned long`[K] - the ctime of the file before the change.
* `new_ctime`:`unsigned long`[K] - the ctime of the file after the change.

## Hooks
### fd_install
#### Type
kprobe
#### Purpose
Catch the open of a file and set the event of file_modification to be submitted for it

### filp_close
#### Type
kprobe
#### Purpose
Catch the close of a file and remove it from cache of files t submit the event for

### file_update_time
#### Type
kprobe + kretprobe
#### Purpose
Catch the file ctime change and submit the event if marked to be submitted

### file_modified
#### Type
kprobe + kretprobe
#### Purpose
Catch the file ctime change and submit the event if marked to be submitted

## Example Use Case

```console
./tracee -e file_modification
```

## Note
Only the first event of file modification is submitted between the open and the close of a file by a process. 
This is to reduce the amount of file modification events on a file which might be a lot. 
That means that the event is not submitted for each write to the file.

## Issues
The file_modification event could be submitted more than once between the open and the close of a file by a process.
This is due to the use of an LRU map, which acts as a cache of files that the event should be submitted on.
Entries of the map are evicted when it is full, thus information about whether an event should be submitted for a 
specific file might be lost, and a new event would be submitted even though such an event was submitted before. 

## Related Events

# mem_prot_alert

## Intro
mem_prot_alert - access protection change of some memory region is suspicious for malicious activity or leave it exposed to one.

## Description
An event marking that a memory region protection access change is suspicious for malicious activity.
Memory access protection changes might expose writeable memory to execution, or hide its possible execution.
The specific alert is passed through the event arguments.

## Arguments
* `alert`:`u32`[K] - the specific alert rose. Will be changed to a meaningful string with the `parse-args` flag on.
* `addr`:`void*`[K] - the start address of the memory region the alert is on.
* `len`:`size_t`[K] - the length of the memory region the alert is on.
* `prot`:`int`[K] - the new access protection for the memory region.
* `prev_prot`:`int` [K] - the previous access protection of the memory region.
* `pathname`:`const char*`[K,OPT] - the path of the file related to the memory region, if there is a related file.
* `dev`:`dev_t`[K,OPT] - the device of the file related to the memory region, if there is a related file.
* `inode`:`unsigned long`[K,OPT] - the inode of the file related to the memory region, if there is a related file.
* `ctime`:`u64`[K,OPT] - the last change time of the file related to the memory region, if there is a related file.

### Alert argument values
The value given can be translated to a meaningful string using the parsing function in the `trace` package.
Here are the current possible values:
* "Mmaped region with W+E permissions!" - a mmap operation creating a memory that is exposed to dynamic code execution.
* "Protection changed to Executable!" - the access protection of the memory region expose it to execution, after some different access protection in the past.
* "Protection changed from E to W+E!" - the access protection of the memory region now enable dynamic modification and execution, enabling dynamic code execution.
* "Protection changed from W to E!" - the access protection of the memory region reduced from dynamic code execution, but still exposed to execution of pre-written code. Might be some evasion attempt.

## Hooks
### security_mmap_addr
#### Type
LSM hook
#### Purpose
Catch the mmap of a memory, getting access to its access protection.

### security_file_mprotect
#### Type
LSM hook
#### Purpose
Catch the change of access protection of a memory.

### sys_enter
#### Type
raw tracepoint
#### Purpose
Extraction information from syscall arguments for deeper hooks oeration.

## Related Events
`security_mmap_addr`,`security_file_mprotect`,`security_mmap_file`,`mmap`,`mprotect`
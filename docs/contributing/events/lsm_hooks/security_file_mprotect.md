# security_file_mprotect

## Intro
security_file_mprotect - check permissions before changing the memory access protection of some memory region

## Description
The event marks an attempt to change the access protection of some memory region, probably by the `mprotect` or
`pkey_mprotect` syscalls.
The event is triggered by the permissions check for the operation, as LSM hook.
The event gives insight on the new access protection, as well as information on the memory addresses the attempt
operation is on.
This is a useful event to tracee memory protection changes originated by a user.
Notice that the change of protection is applied to the pages containing the address range given, not only for given
range.

## Arguments
* `pathname`:`const char*`[K] - the path of the file associated with the memory region.
* `prot`:`int`[K] - the new access protection for the memory region. Will be changed to a string representation if `parse-args` flag was used.
* `ctime`:`unsigned long`[K] - the creation time of the file associated with the memory region.
* `prev_prot`:`int`[K] - the previous access protection for the memory region. Will be changed to a string representation if `parse-args` flag was used.
* `addr`:`void*`[K] - the start of virtual memory address to change its access protection.
* `len`:`size_t`[K] - the length of the memory to apply the new protection on.
* `pkey`:`int`[K,OPT] - the protection key used for the operation. Available only if invoking syscall is `pkey_mprotect`.

## Hooks
### security_file_mprotect
#### Type
LSM hook
#### Purpose
The LSM hook for the `mprotect` related syscalls - `mprotect` and `pkey_mprotect`.

## Related Events
`mprotect`,`pkey_mprotect`
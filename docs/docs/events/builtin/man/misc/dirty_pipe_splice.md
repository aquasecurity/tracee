---
title: TRACEE-DIRTY-PIPE-SPLICE
section: 1
header: Tracee Event Manual
---

## NAME

**dirty_pipe_splice** - dirty pipe vulnerability exploitation detection

## DESCRIPTION

Triggered when the kernel's `do_splice` function is called in conditions that could be exploited by the "Dirty Pipe" vulnerability (CVE-2022-0847). This event specifically monitors for splice operations that could potentially be used to overwrite read-only files, which was the core mechanism of the Dirty Pipe exploit.

The Dirty Pipe vulnerability allowed unprivileged users to overwrite data in read-only files, potentially leading to privilege escalation. This event helps detect exploitation attempts or similar techniques.

## EVENT SETS

**none**

## DATA FIELDS

**inode_in** (*uint64*)
: The inode number of the input file in the splice operation

**in_file_type** (*uint16*)
: The type of the input file being spliced

**in_file_path** (*string*)
: The path of the input file in the splice operation

## DEPENDENCIES

**Kernel Probe:**

- do_splice (kprobe + kretprobe, required): Kernel splice operation function

**Kernel Symbol:**
- pipe_write (required): Pipe write function symbol for analysis

## USE CASES

- **Vulnerability exploitation detection**: Detect potential Dirty Pipe or similar exploitation attempts

- **Security monitoring**: Monitor splice operations for suspicious patterns

- **Threat hunting**: Identify unusual splice operations that could indicate malicious activity

- **System security analysis**: Analyze splice usage for security assessment and compliance

- **Incident response**: Investigate potential exploitation attempts using splice operations

## RELATED EVENTS

- **vfs_write**: VFS write operations that may be affected by splice
- **file_modification**: File modification events related to splice operations
- **Security file events**: Related file security monitoring
- **Vulnerability detection events**: Related security vulnerability monitoring

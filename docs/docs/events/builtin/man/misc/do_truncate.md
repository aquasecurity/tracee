---
title: TRACEE-DO-TRUNCATE
section: 1
header: Tracee Event Manual
---

## NAME

**do_truncate** - file truncation operation monitoring

## DESCRIPTION

Triggered when a file truncation operation is performed using the kernel's `do_truncate` function. This event captures file size reduction operations, which can completely clear file contents or reduce files to a specific size, providing monitoring of potentially destructive file operations.

File truncation can be used to clear sensitive data, reduce file sizes, or as part of normal application operations, making this event valuable for security and data integrity monitoring.

## EVENT SETS

**none**

## DATA FIELDS

**pathname** (*string*)
: The path of the file being truncated

**inode** (*uint64*)
: The inode number of the file on the device

**dev** (*uint32*)
: The device identifier where the file resides

**length** (*uint64*)
: The new size to which the file is being truncated

## DEPENDENCIES

**Kernel Probe:**

- do_truncate (required): Kernel file truncation function

## USE CASES

- **Data destruction monitoring**: Track file truncation operations that remove data

- **Security analysis**: Detect potential evidence elimination or data destruction

- **File integrity monitoring**: Monitor file size changes and content modification

- **Storage management**: Track file size reduction operations and space recovery

- **Application monitoring**: Understand application file management patterns

## RELATED EVENTS

- **file_modification**: General file modification detection
- **vfs_write**: File write operations
- **unlink**: File deletion operations
- **open**: File opening with truncation flags

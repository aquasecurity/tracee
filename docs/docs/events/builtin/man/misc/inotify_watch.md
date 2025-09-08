---
title: TRACEE-INOTIFY-WATCH
section: 1
header: Tracee Event Manual
---

## NAME

**inotify_watch** - filesystem watch setup monitoring

## DESCRIPTION

Triggered when an inotify watch is established on a file or directory through the kernel's inotify subsystem. This event captures the setup of filesystem monitoring watches, which applications use to receive notifications about file and directory changes in real-time.

Inotify watches are commonly used by applications for file monitoring, but can also be used by malware for surveillance purposes, making this event valuable for security monitoring.

## EVENT SETS

**none**

## DATA FIELDS

**pathname** (*string*)
: The path of the file or directory being watched

**inode** (*uint64*)
: The inode number of the file or directory

**dev** (*uint32*)
: The device identifier where the file or directory resides

## DEPENDENCIES

**Kernel Probe:**

- inotify_find_inode (kprobe + kretprobe, required): Inotify inode lookup function

## USE CASES

- **Surveillance detection**: Identify processes setting up file or directory watches

- **Security monitoring**: Detect potential malware surveillance of sensitive files

- **Application monitoring**: Track filesystem monitoring usage by legitimate applications

- **System behavior analysis**: Understand filesystem watch patterns and usage

- **Privacy monitoring**: Detect unauthorized file monitoring activities

## RELATED EVENTS

- **file_modification**: File change detection that may trigger inotify events
- **open**: File access operations that may be monitored
- **vfs_write**: File modifications that trigger inotify notifications
- **Process monitoring events**: Related process behavior monitoring

# security_path_notify

## Intro

security_path_notify - An event capturing the registration of filesystem notifications.

## Description

This event captures all attempts to register a filesystem notification. Filesystem notifications allow a user to receive information about events occurring in the filesystem, by specifying a filesystem object and a set of events to monitor.

This is done using any of 3 filesystem notification APIs: `dnotify`, `inotify` and `fanotify`. `fanotify` even allows responding to filesystem operations by deciding if they should pass or fail. All 3 APIs use the underlying `fsnotify` system in the kernel. While registering a filesystem watch (request for notification), these APIs call `security_path_notify` to determine if any LSM hooks want to block the operation.

By hooking `security_path_notify`, this program can capture any attempt to register a filesystem watch. The event includes details on the filesystem path for which the watch is being registered and the requested filesystem events to monitor.

## Arguments

* `pathname`:`const char*`[K] - filesystem path for which the watch is being registered.
* `inode`:`unsigned long`[K] - inode of the filesystem object
* `dev`:`dev_t`[K] - device of the filesystem object
* `mask`:`u64`[K] - mask representing the filesystem events which should be monitored. These flags are parsed if the `parse-arguments` option is specified.
* `obj_type`:`unsigned int`[K] - the type of filesystem object to be watched. This value is parsed if the `parse-argumetns` option is specified.

# 

## Hooks

### security_path_notify

#### Type

kprobe

#### Purpose

Catch security checks for registering a filesystem notification.

## Example Use Case

Can be used to catch attempts to register filesystem notifications for a certain filesystem object using any of `dnotify`, `inotify` or `fanotify` APIs.

## Issues

## Related Events

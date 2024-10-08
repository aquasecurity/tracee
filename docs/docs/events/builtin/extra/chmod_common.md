# chmod_common

## Intro

chmod_common - An event capturing changes to access permissions of files and directories.

## Description

This event captures any changes to the current working directory (typically by using the `chmod` and similar syscalls).

## Arguments

* `pathname`:`const char*`[K] - path of the file or directory
* `mode`:`mode_t`[K] - the mode to apply to the file or directory

## Hooks

### chmod_common

#### Type

kprobe

#### Purpose

Catch access permissions changes of files and directories.

## Example Use Case

## Issues

## Related Events

`chmod`, `fchmod`, `fchmodat`

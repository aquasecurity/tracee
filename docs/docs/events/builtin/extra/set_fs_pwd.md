# set_fs_pwd

## Intro

set_fs_pwd - An event capturing changes to the current working directory.

## Description

This event captures any changes to the current working directory (typically by using the `chdir` and `fchdir` syscalls).

## Arguments

* `unresolved_pathname`:`const char*`[K,TOCTOU,OPT] - unresolved, user-supplied path which the current working directory is being changed to (only relevant to directory changes using the `chdir` syscall).
* `resolved_pathname`:`const char*`[K] - the fully resolved filesystem path which the current working directory is being changed to.

## Hooks

### set_fs_pwd

#### Type

kprobe

#### Purpose

Catch changes to the current working directory.

## Example Use Case

## Issues

## Related Events

`chdir`, `fchdir`

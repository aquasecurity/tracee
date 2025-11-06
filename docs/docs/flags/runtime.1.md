---
title: TRACEE-RUNTIME
section: 1
header: Tracee Runtime Flag Manual
date: 2025/12
...

## NAME

tracee **\-\-runtime** - Control runtime configurations

## SYNOPSIS

tracee **\-\-runtime** [workdir=*path*] [**\-\-runtime** ...]

## DESCRIPTION

The **\-\-runtime** flag allows you to control runtime configurations for Tracee.

### Options

- **workdir**=*path*
  Set the path where Tracee will install or lookup its resources. The default value is `/tmp/tracee`.

  Example:
  ```console
  --runtime workdir=/tmp/tracee
  ```

## EXAMPLES

1. Use the default working directory:
   ```console
   --runtime workdir=/tmp/tracee
   ```

2. Set a custom working directory:
   ```console
   --runtime workdir=/var/lib/tracee
   ```

3. Using the short form:
   ```console
   -r workdir=/opt/tracee
   ```


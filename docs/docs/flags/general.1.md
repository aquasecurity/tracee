---
title: TRACEE-GENERAL
section: 1
header: Tracee General Flag Manual
date: 2025/01
...

## NAME

tracee **\-\-general** - Control general configurations

## SYNOPSIS

tracee **\-\-general** [workdir=*path*] [**\-\-general** ...]

## DESCRIPTION

The **\-\-general** flag allows you to control general configurations for Tracee.

### Options

- **workdir**=*path*
  Set the working directory where Tracee stores temporary files and artifacts. The default value is `/tmp/tracee`.

  Example:
  ```console
  --general workdir=/tmp/tracee
  ```

## EXAMPLES

1. Use the default working directory:
   ```console
   --general workdir=/tmp/tracee
   ```

2. Set a custom working directory:
   ```console
   --general workdir=/var/lib/tracee
   ```

3. Using the short form:
   ```console
   -g workdir=/opt/tracee
   ```


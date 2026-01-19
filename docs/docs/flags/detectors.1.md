---
title: TRACEE-DETECTORS
section: 1
header: Tracee Detectors Flag Manual
date: 2026/01
...

## NAME

tracee **\-\-detectors** - Configure YAML detector search directories

## SYNOPSIS

tracee **\-\-detectors** [path...] [**\-\-detectors** path...]

## DESCRIPTION

The **\-\-detectors** flag lets you add directories or files to search for YAML detectors and shared lists.

Each path can be a directory or a YAML file. If not specified, Tracee uses the default search path `/etc/tracee/detectors`.

## EXAMPLES

1. Use the default search path:
   ```console
   tracee
   ```

2. Add a custom directory:
   ```console
   --detectors /custom/detectors
   ```

3. Add multiple directories:
   ```console
   --detectors /dir1 --detectors /dir2
   ```

4. Add a specific YAML detector file:
   ```console
   --detectors ./detectors/suspicious_exec.yaml
   ```

5. Config file format:
   ```yaml
   detectors:
     - /custom/path1
     - /custom/path2
   ```

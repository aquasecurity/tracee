---
title: TRACEE-SIGNATURES
section: 1
header: Tracee Signatures Flag Manual
date: 2025/11
...

## NAME

tracee **\-\-signatures** - Configure signature search paths

## SYNOPSIS

tracee **\-\-signatures** [search-paths=*path1*[,*path2*...]] [**\-\-signatures** ...]

## DESCRIPTION

The **\-\-signatures** flag allows you to configure directories where Tracee will search for signatures in Go plugin (.so) format. Signatures are security detection rules that analyze events to identify suspicious or malicious behavior.

If no search paths are specified, Tracee will search for signatures in the `signatures` directory relative to the Tracee executable.

### Options

- **search-paths**=*path1*[,*path2*...]
  Specify one or more directories where Tracee should search for signature plugins. Multiple paths can be provided as a comma-separated list. Paths can be absolute or relative.

  Example:
  ```console
  --signatures search-paths=/path/to/signatures
  ```

  Multiple paths:
  ```console
  --signatures search-paths=/path1,/path2,/path3
  ```

## EXAMPLES

1. Use a single custom signatures directory:
   ```console
   --signatures search-paths=/opt/tracee/signatures
   ```

2. Use multiple signatures directories:
   ```console
   --signatures search-paths=/usr/local/signatures,/opt/custom-signatures
   ```

3. Use relative paths:
   ```console
   --signatures search-paths=./signatures,../other-signatures
   ```

4. Combine multiple signature flags:
   ```console
   --signatures search-paths=/path1 --signatures search-paths=/path2
   ```

5. Use with policies to enable signature-based detection:
   ```console
   --signatures search-paths=/opt/tracee/signatures --policy ./policy.yaml
   ```


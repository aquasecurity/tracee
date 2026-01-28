# Tracee Scripts

This directory contains utility scripts for developing, building, testing, and debugging Tracee.

## Directory Structure

### `debugging/`

Tools for debugging and analyzing Tracee components:

- **[inspect_bpf_prog.sh](debugging/inspect_bpf_prog.md)** - Inspect and measure eBPF programs in BPF object files. Supports program size measurement, assembly dumping, and comparing between builds.

### `installation/`

Scripts for installing dependencies and preparing environments:

- `install-deps-ubuntu.sh` - Install build dependencies on Ubuntu
- `install-deps-centos.sh` - Install build dependencies on CentOS
- `install-deps-alpine.sh` - Install build dependencies on Alpine Linux
- `install-clang.sh` - Install specific LLVM/Clang versions
- `prepare-ami.sh` - Prepare AWS AMI for CI/CD
- `pull-test-images.sh` - Pull container images for testing

### Core Scripts

- `btfhub.sh` - Manage BTFhub integration for CO-RE support
- `checkpatch.sh` - Run Linux kernel style checks on patches
- `system-info.sh` - Display system information for debugging
- `sync_system_time.sh` - Synchronize system time (useful in VMs)
- `tracee_start.sh` / `tracee_stop.sh` - Start/stop Tracee with common configurations
- `run_test_scripts.sh` - Run integration test scripts
- `verify_man_md_sync.sh` - Verify man pages and markdown docs are in sync

### Library Scripts

Common utilities sourced by other scripts:

**General Purpose Libraries:**
- `lib.sh` - Main library that imports all other libs
- `lib_log.sh` - Logging functions (info, error, warn, etc.)
- `lib_print.sh` - Formatted output utilities
- `lib_git.sh` - Git operations
- `lib_test.sh` - Test framework utilities
- `lib_testing.sh` - Additional test helpers
- `lib_misc.sh` - Miscellaneous utilities
- `lib_internal.sh` - Internal helper functions

**Tracee-Specific Library:**
- `tracee_common.sh` - Common functions for `tracee_start.sh` and `tracee_stop.sh`

## Usage

Most scripts include a `--help` flag for detailed usage information:

```bash
./script-name.sh --help
```

## Contributing

When adding new scripts:

1. Follow the existing structure and naming conventions
2. Add a shebang line (`#!/bin/bash`) and set executable permissions
3. Source `lib.sh` for consistent logging and utilities
4. Include usage/help documentation
5. Update this README with a brief description
6. Consider adding the script to the appropriate subdirectory

For script style guidelines, see [.cursor/rules/shell-style-guide.mdc](../.cursor/rules/shell-style-guide.mdc).

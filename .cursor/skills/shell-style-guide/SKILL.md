---
name: shell-style-guide
description: Enforce Tracee shell standards with shellcheck and shfmt. Use when editing shell scripts, YAML run blocks, or shell code blocks in markdown.
---

# Shell Style Guide

## Quick Start

Apply these requirements for any shell work:

1. ShellCheck must pass with zero errors.
2. Format with shfmt based on shell type.
3. Use braces for variable expansion (`${var}`).
4. Keep `scripts/lib*.sh` POSIX sh compatible.

## Commands

- Bash file:
  - `shfmt -i 4 -ci -bn -sr -w <file>`
  - `shellcheck -s bash <file>`
- POSIX sh file:
  - `shfmt -p -i 4 -ci -bn -sr -w <file>`
  - `shellcheck -s sh <file>`
- Library file:
  - `shfmt -p -i 4 -ci -bn -sr -w scripts/lib_example.sh`
  - `shellcheck -s sh -x scripts/lib_example.sh`

## Core Rules

- Use `#!/bin/bash` for executables unless strict POSIX compatibility is required.
- Use `#!/bin/sh` for `scripts/lib*.sh`.
- Do not use Bash-only features in POSIX sh (`local`, arrays, `[[ ]]`, process substitution).
- Quote expansions and use explicit error handling (`set -euo pipefail` for Bash, `set -eu` for POSIX).
- For POSIX sh helper variables in non-library scripts, use single underscore namespacing.

## Detailed Reference

For the complete Tracee shell style details, see [reference.md](reference.md).

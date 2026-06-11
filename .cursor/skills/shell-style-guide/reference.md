# Tracee Shell Reference

This reference captures the detailed shell constraints used by Tracee.
Use it when the task needs exact style behavior beyond the quick checklist.

## Required Tooling

- ShellCheck: zero errors required.
- shfmt with project flags:
  - Bash: `shfmt -i 4 -ci -bn -sr -w <file>`
  - POSIX sh: `shfmt -p -i 4 -ci -bn -sr -w <file>`

## Script Types

- Executables default to Bash (`#!/bin/bash`).
- Library files `scripts/lib*.sh` must remain POSIX sh (`#!/bin/sh`).
- Embedded shell blocks in YAML and markdown must be linted/formatted by actual shell mode.

## POSIX Compatibility Notes

In POSIX sh:
- Do not use `local`.
- Do not use arrays.
- Do not use `[[ ]]`; use `[ ]`.
- Use `=` for string equality in `[ ]`.
- Avoid Bash string replacement, regex matching, and process substitution.

## Variable and Naming Rules

- Use `${var}` expansion style.
- Quote variable expansions by default.
- In library internals (`scripts/lib*.sh`), reserve `__` namespace for helpers and status variables.
- In non-library POSIX scripts, use `_function_name_var` style for internal helper variables.

## Validation Workflow

Before commit:
1. Format changed shell files with shfmt.
2. Run ShellCheck in correct mode.
3. If libraries changed, run `./scripts/lib_test.sh`.

## References

- [Google Shell Style Guide](https://google.github.io/styleguide/shellguide.html)
- [ShellCheck](https://www.shellcheck.net/)
- [shfmt](https://github.com/mvdan/sh)

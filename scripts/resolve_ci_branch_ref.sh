#!/bin/sh
#
# Resolve the CI branch ref from the ci-branch-ref file.
#
# Reads the first line of the file, trims whitespace, and falls back to
# "main" when the file is missing or empty. Prints the resolved value to
# stdout so callers can capture it with command substitution.
#
# Usage: scripts/resolve_ci_branch_ref.sh [PATH_TO_FILE]
#   PATH_TO_FILE defaults to "ci-branch-ref" in the repository root.
#

set -eu

_file="${1:-ci-branch-ref}"
_branch=""

if [ -f "${_file}" ]; then
    _branch=$(sed -n '1p' "${_file}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
fi

[ -z "${_branch}" ] && _branch="main"

printf '%s\n' "${_branch}"

#!/bin/bash
#
# Synchronizes system time using available time sync methods.
# Tries chronyc first, then systemd-timesyncd as a fallback.
#
# Returns exit code 0 on success, 1 on failure.
# CI environments can use 'continue-on-error: true' to prevent
# time sync failures from blocking the pipeline.
#

set -euo pipefail

__LIB_DIR="${0%/*}"
# shellcheck disable=SC1091
. "${__LIB_DIR}/lib.sh"

# requirements
require_cmds date awk

info "Forcing time sync..."

# Capture time before sync
before=$(date -u)
before_epoch=$(date +%s.%N)

# Attempt to sync time using available methods
sync_method=""
if command -v chronyc > /dev/null 2>&1; then
    if chronyc makestep > /dev/null 2>&1; then
        sync_method="chronyc makestep"
    fi
fi

if [[ -z "${sync_method}" ]] && command -v systemctl > /dev/null 2>&1; then
    if systemctl restart systemd-timesyncd > /dev/null 2>&1; then
        sync_method="systemd-timesyncd restart"
    fi
fi

# Capture time after sync
after=$(date -u)
after_epoch=$(date +%s.%N)

# Report results
if [[ -n "${sync_method}" ]]; then
    diff=$(awk "BEGIN {printf \"%.9f\", ${after_epoch} - ${before_epoch}}")
    info "Time synced successfully using: ${sync_method}"
    info "  Before: ${before}"
    info "  After:  ${after}"
    info "  Diff:   ${diff}s"
    exit 0
else
    error "Current time: ${after}"
    die "All time sync methods failed"
fi

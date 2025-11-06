#!/bin/bash

__LIB_DIR="${0%/*}"
# shellcheck disable=SC1091
. "${__LIB_DIR}/lib.sh"

# Default timeout for waiting for apt locks (in seconds)
DEFAULT_TIMEOUT=300

show_help() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Disable unattended upgrades and wait for apt locks to be released.

OPTIONS:
    -h, --help              Show this help message and exit
    -t, --timeout SECONDS   Set timeout for waiting for apt locks (default: ${DEFAULT_TIMEOUT} seconds)

EXAMPLES:
    $(basename "$0")                    # Use default ${DEFAULT_TIMEOUT}-second timeout
    $(basename "$0") -t 600             # Wait up to 600 seconds for apt locks
    $(basename "$0") --timeout 120      # Wait up to 120 seconds for apt locks

DESCRIPTION:
    This script disables Ubuntu's unattended-upgrades system and waits for any
    existing apt locks to be released. It will attempt to gracefully terminate
    running processes and, if necessary, forcefully kill them after the timeout.

    The script performs the following actions:
    1. Stops and masks systemd units related to automatic updates
    2. Waits for unattended-upgrades processes to finish
    3. Waits for apt locks to be released
    4. Purges unattended-upgrades and related packages

EOF
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -h | --help)
            show_help
            exit 0
            ;;
        -t | --timeout)
            if [[ -z "$2" ]] || [[ "$2" =~ ^- ]] || ! [[ "$2" =~ ^[0-9]+$ ]]; then
                die "timeout requires a positive integer (seconds)"
            fi
            TIMEOUT="$2"
            shift 2
            ;;
        *)
            die "Unknown option '$1'. Use --help for usage information."
            ;;
    esac
done

TIMEOUT="${TIMEOUT:-$DEFAULT_TIMEOUT}"
export DEBIAN_FRONTEND=noninteractive

if [[ -f /etc/os-release ]]; then
    # shellcheck source=/dev/null
    . /etc/os-release
    if [[ ! "${ID}" == "ubuntu" ]]; then
        info "Not running on Ubuntu, exiting"
        exit 0
    fi
fi

require_cmds apt-get fuser pgrep pkill systemctl rm sleep

wait_for_apt_locks() {
    locked_files=(
        "/var/lib/dpkg/lock"
        "/var/lib/dpkg/lock-frontend"
        "/var/lib/apt/lists/lock"
        "/var/cache/apt/archives/lock"
    )

    local timeout=${1:-$DEFAULT_TIMEOUT}
    local elapsed=0
    local wait_interval=2
    local unattended_bin
    unattended_bin=$(which unattended-upgrade) || true
    unattended_bin=${unattended_bin:-/usr/bin/unattended-upgrade}

    info "Checking for unattended-upgrades (timeout: ${timeout} seconds)..."
    while pgrep -f "${unattended_bin}" > /dev/null 2>&1; do
        if ((elapsed >= timeout)); then
            info "Timed out waiting for unattended-upgrades to finish. Attempting to kill..."
            pkill -SIGKILL -f "${unattended_bin}" || true
            break
        fi

        info "unattended-upgrades is still running. Waiting... (${elapsed}s/${timeout}s)"
        pkill -SIGTERM -f "${unattended_bin}" || true
        sleep $wait_interval
        ((elapsed += wait_interval))
    done

    # Reset timer for apt locks check
    elapsed=0

    info "Checking for apt locks (timeout: ${timeout} seconds)..."
    while :; do
        locked=false
        for lock in "${locked_files[@]}"; do
            if fuser "${lock}" > /dev/null 2>&1; then
                locked=true
                break
            fi
        done
        if ! ${locked}; then
            info "All apt locks are free."
            break
        fi

        if ((elapsed < timeout)); then
            info "Waiting for apt locks to be released... (${elapsed}s/${timeout}s)"
            sleep $wait_interval
            ((elapsed += wait_interval))
            continue
        fi

        info "Timed out waiting for apt locks to be released. Attempting to kill locking processes."
        for lock in "${locked_files[@]}"; do
            fuser -k -SIGTERM "${lock}" > /dev/null 2>&1 || true
        done

        sleep 2 # give some time for processes to terminate gracefully

        for lock in "${locked_files[@]}"; do
            fuser -k -SIGKILL "${lock}" > /dev/null 2>&1 || true
            rm -f "${lock}" || true
        done

        warn "Forced removal of processes locking apt. System may be in an inconsistent state."
        break
    done
}

disable_unattended_upgrades() {
    local timeout=${1:-$DEFAULT_TIMEOUT}

    info "Stopping and masking auto-apt/unattended units..."
    # masking beats accidental re-enables
    units=(
        apt-daily.timer
        apt-daily-upgrade.timer
        unattended-upgrades.service
        apt-daily.service
        apt-daily-upgrade.service
        apt-news.timer
        apt-news.service
    )

    for u in "${units[@]}"; do
        systemctl stop "${u}" 2> /dev/null || true
        systemctl disable --now "${u}" &> /dev/null || true
        systemctl mask "${u}" 2> /dev/null || true
    done

    systemctl daemon-reload

    # This is a pain point. Make sure to always disable anything touching the
    # dpkg database, otherwise it will fail with locking errors.

    info "Purging packages that re-enable unattended tasks..."
    systemctl stop unattended-upgrades 2> /dev/null || true
    systemctl disable --now unattended-upgrades 2> /dev/null || true

    wait_for_apt_locks "${timeout}"
    apt-get -y purge unattended-upgrades ubuntu-advantage-tools || true

    info "Unattended upgrades disabled successfully"
}

# main
disable_unattended_upgrades "${TIMEOUT}"

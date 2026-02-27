#!/bin/bash
#
# Basic integration test: run evt stress with a scenario, then run the Tracee
# binary (not container) to detect events emitted by evt. Evt runs with
# --auto-tracee=false and waits for ENTER; the script starts Tracee, then
# signals evt to continue. Tracee JSON output is printed to stdout and
# persisted to tracee-events-<timestamp>.json in the repo root.
#
# Usage: ./scripts/evt-tracee-test.sh [EVT_BINARY] [SUITE_YAML]
#   EVT_BINARY   - path to evt (default: ./dist/evt)
#   SUITE_YAML   - path to suite file (default: docs/contributing/evt-suite-example.yaml)
#
# Requires: docker, evt binary, tracee binary. Run from repo root.
# The script builds evt and tracee via 'make evt' and 'make tracee' if missing in dist/.
#
# Env: TRACEE_BINARY, TRACEE_EVENTS, EVT_SCENARIO, CONTAINER_WAIT_TIMEOUT, EVT_INITIAL_DELAY_SEC, TRIGGER_DELAY_SEC, TRACEE_MIN_RUN_AFTER_TRIGGER, TRACEE_GRACEFUL_TIMEOUT, TRACEE_JSON_LOG
# Tracee is stopped gracefully (SIGTERM) when evt stress completes.
#

set -euo pipefail

# Resolve script dir (works when script is run as ./script or via bash script)
_script_path="${BASH_SOURCE[0]:-$0}"
readonly SCRIPT_DIR="$(cd "$(dirname "${_script_path}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

readonly LOG_PREFIX="[evt-tracee-test]"

log() {
    echo "${LOG_PREFIX}" "$@" >&2
}

log_step() {
    echo "" >&2
    echo "${LOG_PREFIX} === $* ===" >&2
}

# Config (override via env)
: "${EVT_BINARY:=}"
: "${SUITE_YAML:=}"
: "${TRACEE_BINARY:=}"
: "${EVT_SCENARIO:=smoke}"
: "${CONTAINER_WAIT_TIMEOUT:=30}"
: "${EVT_INITIAL_DELAY_SEC:=5}"
: "${TRIGGER_DELAY_SEC:=15}"
: "${TRACEE_GRACEFUL_TIMEOUT:=10}"
: "${TRACEE_JSON_LOG:=}"
# Minimum seconds to keep Tracee running after we send ENTER to evt (so evt can run triggers and we don't kill Tracee before evt finalizes).
: "${TRACEE_MIN_RUN_AFTER_TRIGGER:=25}"

# Temp fifo for signaling evt ("Press ENTER when Tracee is ready")
FIFO=""
FIFO_FD=""
EVT_PID=""
TRIGGER_PID=""
TRACEE_PID=""
TRACEE_PGID=""
# Stderr fifo for Tracee so a reader process can flush to tracee.log (avoids Go logger buffering)
FIFO_STDERR=""
TRACEE_CAT_PID=""

cleanup() {
    if [[ -n "${TRACEE_CAT_PID}" ]] && kill -0 "${TRACEE_CAT_PID}" 2> /dev/null; then
        kill "${TRACEE_CAT_PID}" 2> /dev/null || true
    fi
    if [[ -n "${FIFO_STDERR}" ]] && [[ -p "${FIFO_STDERR}" ]]; then
        rm -f "${FIFO_STDERR}"
    fi
    if [[ -n "${TRACEE_PGID}" ]]; then
        if kill -0 -"${TRACEE_PGID}" 2> /dev/null || sudo kill -0 -"${TRACEE_PGID}" 2> /dev/null; then
            log "Cleanup: stopping Tracee process group (SIGTERM)..."
            sudo kill -TERM -"${TRACEE_PGID}" 2> /dev/null || kill -TERM -"${TRACEE_PGID}" 2> /dev/null || true
            sleep "${TRACEE_GRACEFUL_TIMEOUT:-5}"
            sudo kill -9 -"${TRACEE_PGID}" 2> /dev/null || kill -9 -"${TRACEE_PGID}" 2> /dev/null || true
        fi
    elif [[ -n "${TRACEE_PID}" ]]; then
        if kill -0 "${TRACEE_PID}" 2> /dev/null || sudo kill -0 "${TRACEE_PID}" 2> /dev/null; then
            log "Cleanup: stopping Tracee (SIGTERM)..."
            sudo kill -TERM "${TRACEE_PID}" 2> /dev/null || kill -TERM "${TRACEE_PID}" 2> /dev/null || true
            sleep "${TRACEE_GRACEFUL_TIMEOUT:-5}"
            sudo kill -9 "${TRACEE_PID}" 2> /dev/null || kill -9 "${TRACEE_PID}" 2> /dev/null || true
        fi
    fi
    if [[ -n "${TRIGGER_PID}" ]] && kill -0 "${TRIGGER_PID}" 2> /dev/null; then
        kill "${TRIGGER_PID}" 2> /dev/null || true
    fi
    if [[ -n "${EVT_PID}" ]] && kill -0 "${EVT_PID}" 2> /dev/null; then
        kill "${EVT_PID}" 2> /dev/null || true
    fi
    if [[ -n "${FIFO_FD}" ]]; then
        exec 3>&- 2> /dev/null || true
    fi
    if [[ -n "${FIFO}" ]] && [[ -p "${FIFO}" ]]; then
        rm -f "${FIFO}"
    fi
}
trap cleanup EXIT

usage() {
    echo "Usage: $0 [EVT_BINARY] [SUITE_YAML]" >&2
    echo "  EVT_BINARY   path to evt (default: ${REPO_ROOT}/dist/evt)" >&2
    echo "  SUITE_YAML   path to suite YAML (default: ${REPO_ROOT}/docs/contributing/evt-suite-example.yaml)" >&2
    echo "" >&2
    echo "Env: TRACEE_BINARY, TRACEE_EVENTS, EVT_SCENARIO, CONTAINER_WAIT_TIMEOUT, EVT_INITIAL_DELAY_SEC, TRIGGER_DELAY_SEC, TRACEE_MIN_RUN_AFTER_TRIGGER, TRACEE_GRACEFUL_TIMEOUT, TRACEE_JSON_LOG" >&2
    exit 1
}

# Build binary if missing. Usage: ensure_binary <path> <make_target>
ensure_binary() {
    local path="$1"
    local make_target="$2"
    if [[ -f "${path}" ]]; then
        log "Binary exists: ${path}"
        return 0
    fi
    log "Binary missing: ${path}; running 'make ${make_target}' from repo root..."
    ( cd "${REPO_ROOT}" && make "${make_target}" )
    if [[ ! -f "${path}" ]]; then
        log "Error: build did not produce ${path}"
        return 1
    fi
    log "Built: ${path}"
    return 0
}

main() {
    log "Starting (repo root: ${REPO_ROOT})"

    if [[ "${1:-}" = "-h" ]] || [[ "${1:-}" = "--help" ]]; then
        usage
    fi

    local evt_bin="${1:-${REPO_ROOT}/dist/evt}"
    local suite_yaml="${2:-${REPO_ROOT}/docs/contributing/evt-suite-example.yaml}"
    local tracee_bin="${TRACEE_BINARY:-${REPO_ROOT}/dist/tracee}"

    # Normalize to absolute paths when using defaults
    [[ "${evt_bin}" != /* ]] && evt_bin="${REPO_ROOT}/${evt_bin}"
    [[ "${suite_yaml}" != /* ]] && suite_yaml="${REPO_ROOT}/${suite_yaml}"
    [[ "${tracee_bin}" != /* ]] && tracee_bin="${REPO_ROOT}/${tracee_bin}"

    log_step "Step 0: Ensure evt and tracee binaries exist"
    ensure_binary "${evt_bin}" "evt" || { echo "Error: evt binary not found at ${evt_bin}" >&2; exit 1; }
    ensure_binary "${tracee_bin}" "tracee" || { echo "Error: tracee binary not found at ${tracee_bin}" >&2; exit 1; }

    if [[ ! -f "${suite_yaml}" ]]; then
        log "Error: suite YAML not found at ${suite_yaml}"
        exit 1
    fi
    log "Suite YAML: ${suite_yaml}"

    # Fifo under repo root so path is predictable and writable.
    # Open order matters: opening a FIFO for write blocks until a reader opens it.
    # So we must start evt (reader) first, then open for write in this process.
    FIFO="${REPO_ROOT}/.evt-trigger-fifo.$$"
    mkfifo "${FIFO}"
    FIFO_FD=3
    log "Fifo created: ${FIFO}"

    log_step "Step 1: Start evt stress (background)"
    log "  Binary: ${evt_bin}"
    log "  Suite:  ${suite_yaml}"
    log "  Scenario: ${EVT_SCENARIO}"
    log "  Flags: --auto-tracee=false (evt waits for ENTER after printing container scope)"
    # Line-buffer evt's stdout so the script sees "Container scope filter:" in the log
    # (when stdout is not a tty, evt uses full buffering and the line may never appear in time).
    local evt_runner=("${evt_bin}")
    if command -v stdbuf >/dev/null 2>&1; then
        evt_runner=(stdbuf -oL "${evt_bin}")
        log "  Using stdbuf for line-buffered evt output"
    fi
    (
        cd "${REPO_ROOT}"
        "${evt_runner[@]}" stress \
            --events-file "${suite_yaml}" \
            --scenario "${EVT_SCENARIO}" \
            --auto-tracee=false \
            < "${FIFO}"
    ) > "${REPO_ROOT}/evt-stress.log" 2>&1 &
    EVT_PID=$!
    log "  evt started (PID ${EVT_PID}), output -> evt-stress.log"

    # Open fifo for write so we can send ENTER later. This unblocks evt's open-for-read.
    log "  Opening fifo for write (connects to evt stdin)..."
    exec 3>"${FIFO}"
    log "  Fifo connected (fd 3)"

    local evt_stress_log="${REPO_ROOT}/evt-stress.log"
    log "  Giving evt ${EVT_INITIAL_DELAY_SEC}s to start containers and print scope..."
    sleep "${EVT_INITIAL_DELAY_SEC}"

    log "  Waiting for evt to print container scope (timeout ${CONTAINER_WAIT_TIMEOUT}s)..."
    local scope_ids=""
    local waited=0
    while [[ ${waited} -lt ${CONTAINER_WAIT_TIMEOUT} ]]; do
        if [[ -f "${evt_stress_log}" ]]; then
            scope_ids="$(grep "Container scope filter:" "${evt_stress_log}" 2>/dev/null | sed -n 's/.*container=\([^[:space:]]*\).*/\1/p' | tail -1)"
            if [[ -z "${scope_ids}" ]]; then
                scope_ids="$(grep "container=" "${evt_stress_log}" 2>/dev/null | sed -n 's/.*container=\([^[:space:]]*\).*/\1/p' | tail -1)"
            fi
            if [[ -n "${scope_ids}" ]]; then
                log "  Scope line found after ${waited}s"
                break
            fi
        fi
        if [[ $((waited % 5)) -eq 0 ]] && [[ ${waited} -gt 0 ]]; then
            log "  ... still waiting (${waited}s)"
        fi
        sleep 1
        waited=$((waited + 1))
    done

    if [[ -z "${scope_ids}" ]]; then
        log "Error: evt did not print container scope after ${CONTAINER_WAIT_TIMEOUT}s."
        if [[ -f "${evt_stress_log}" ]]; then
            log "evt-stress.log output:"
            cat "${evt_stress_log}" >&2
        else
            log "evt-stress.log is missing."
        fi
        exit 1
    fi
    log "  Scope container IDs (from evt): ${scope_ids}"

    local json_log="${TRACEE_JSON_LOG:-${REPO_ROOT}/tracee-events-$(date +%Y%m%d-%H%M%S).json}"
    local tracee_log="${REPO_ROOT}/tracee.log"

    log_step "Step 2: Run Tracee binary (JSON output)"
    log "  Binary: ${tracee_bin}"
    log "  Scope: container=${scope_ids}"
    log "  JSON log (events): ${json_log}"
    log "  Tracee log (stderr): ${tracee_log}"
    log "  Will send ENTER to evt after ${TRIGGER_DELAY_SEC}s so evt continues triggering."

    # Signal evt to continue after Tracee has had time to start
    (
        sleep "${TRIGGER_DELAY_SEC}"
        printf '\n' >&3
    ) &
    TRIGGER_PID=$!
    log "  Trigger job scheduled (PID ${TRIGGER_PID})"

    # Tracee needs root for eBPF; use sudo if not already root.
    # Use -o json:<path> so Tracee opens and writes the JSON file itself (reliable; no shell redirect/pipe buffering).
    # Use --logging level=info so Tracee logs go to tracee.log without debug noise.
    # Use --events so Tracee subscribes to events (with only --scope and no --events, Tracee subscribes to zero events).
    # Default events match the smoke scenario; pass each as a separate --events flag for reliable parsing.
    : "${TRACEE_EVENTS:=security_file_open,ptrace,sched_process_exec}"
    local tracee_cmd
    if [[ "$(id -u)" -ne 0 ]]; then
        log "  Running Tracee with sudo (eBPF requires root)"
        tracee_cmd=(sudo "${tracee_bin}" --scope "container=${scope_ids}" --enrichment environment --logging level=info -o "json:${json_log}")
    else
        log "  Running Tracee as root"
        tracee_cmd=("${tracee_bin}" --scope "container=${scope_ids}" --enrichment environment --logging level=info -o "json:${json_log}")
    fi
    IFS=',' read -ra _evts <<< "${TRACEE_EVENTS}"
    for _e in "${_evts[@]}"; do
        _e="${_e#"${_e%%[![:space:]]*}"}"
        _e="${_e%"${_e##*[![:space:]]}"}"
        [[ -n "${_e}" ]] && tracee_cmd+=(--events "${_e}")
    done

    # Run Tracee in its own session (setsid) so we can kill its process group without affecting script/evt.
    log "  Exec: ${tracee_cmd[*]}"
    log "  Starting Tracee in background (events -> ${json_log}, stderr -> ${tracee_log})..."
    local tracee_start_ts
    tracee_start_ts=$(date +%s)
    local tracee_runner=("${tracee_cmd[@]}")
    if command -v stdbuf >/dev/null 2>&1; then
        tracee_runner=(stdbuf -oL "${tracee_cmd[@]}")
    fi
    # Use a FIFO for stderr so a reader process flushes to tracee.log (Go logger buffers when stderr is a file).
    FIFO_STDERR="${REPO_ROOT}/.tracee-stderr.$$"
    mkfifo "${FIFO_STDERR}"
    if command -v stdbuf >/dev/null 2>&1; then
        ( stdbuf -oL cat "${FIFO_STDERR}" > "${tracee_log}" ) &
    else
        ( cat "${FIFO_STDERR}" > "${tracee_log}" ) &
    fi
    TRACEE_CAT_PID=$!
    local run_args=("${tracee_log}" "${FIFO_STDERR}" "${tracee_runner[@]}")
    setsid bash -c 'tracee_log=$1; fifo=$2; shift 2; exec "$@" >/dev/null 2>"$fifo"' _ "${run_args[@]}" &
    local pipeline_pid=$!
    TRACEE_PGID="${pipeline_pid}"
    TRACEE_PID="${pipeline_pid}"
    log "  Tracee pipeline PID: ${pipeline_pid} (own session; will stop process group on shutdown)"

    # When evt exits, ensure Tracee has run at least TRIGGER_DELAY_SEC + TRACEE_MIN_RUN_AFTER_TRIGGER seconds
    # (so we don't kill Tracee before evt has had time to run triggers after we send ENTER). Then flush delay, then stop.
    # Use sudo so we can signal root-owned processes (tracee runs under sudo).
    (
        wait "${EVT_PID}" 2>/dev/null || true
        local now elapsed min_run remaining
        now=$(date +%s)
        elapsed=$((now - tracee_start_ts))
        min_run=$((TRIGGER_DELAY_SEC + TRACEE_MIN_RUN_AFTER_TRIGGER))
        if [[ ${elapsed} -lt ${min_run} ]]; then
            remaining=$((min_run - elapsed))
            log "  evt finished; keeping Tracee running ${remaining}s more (min ${min_run}s) so evt could finalize..."
            sleep "${remaining}"
        fi
        log "  Stopping Tracee (3s flush delay, then SIGTERM to process group)..."
        sleep 3
        sudo kill -TERM -"${TRACEE_PGID}" 2>/dev/null || kill -TERM -"${TRACEE_PGID}" 2>/dev/null || true
    ) &
    local shutdown_pid=$!

    # Wait for the pipeline to exit (Tracee will exit when shutdown job sends SIGTERM).
    log "  Waiting for Tracee to finish (will stop when evt stress completes)..."
    wait "${pipeline_pid}" 2>/dev/null
    local tracee_exit=$?
    kill "${shutdown_pid}" 2>/dev/null || true
    log "  Tracee exited with code ${tracee_exit}"

    log_step "Summary"
    local event_count=0
    if [[ -f "${json_log}" ]]; then
        event_count="$(grep -c '"eventName"' "${json_log}" 2>/dev/null | head -1 || echo "0")"
        event_count="${event_count//[^0-9]/}"
        [[ -z "${event_count}" ]] && event_count=0
    fi
    log "  Tracee log (stderr): ${tracee_log}"
    if [[ -f "${tracee_log}" ]] && [[ -s "${tracee_log}" ]]; then
        if [[ ${tracee_exit} -ne 0 ]] || [[ ${event_count} -eq 0 ]]; then
            log "  Last 40 lines of Tracee log:"
            tail -40 "${tracee_log}" | sed 's/^/    /' >&2
        fi
    else
        log "  (Tracee log empty or missing - Tracee may not have started.)"
    fi
    if [[ -f "${json_log}" ]]; then
        local line_count
        line_count="$(wc -l < "${json_log}" 2>/dev/null | head -1 || echo "0")"
        line_count="${line_count//[^0-9]/}"
        [[ -z "${line_count}" ]] && line_count=0
        log "  Events persisted to: ${json_log}"
        log "  Event count: ${event_count} (JSON events with eventName)"
        log "  File lines: ${line_count}"
        if [[ ${event_count} -eq 0 ]]; then
            log "  (No events captured - Tracee may have exited before evt triggered, or scope/perms issue.)"
        fi
    else
        log "  No JSON log file found at ${json_log}"
    fi
    return "${tracee_exit}"
}

main "$@"

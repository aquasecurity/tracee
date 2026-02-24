#!/bin/bash
#
# Run evt stress with a scenario, collecting performance data during stress.
# Orchestrates: start evt, detect "Tracee is ready (PID: N)" from evt output,
# start CPU profile capture in background, wait for evt stress to finish,
# then fetch heap, metrics, generate charts, and optionally kill Tracee.
#
# Flow:
#   1. Start evt stress (evt prints "Tracee is ready (PID: N)" when ready)
#   2. On ready: start CPU profile capture in background (runs until PROFILE_SECONDS)
#   3. Wait for evt stress to finish
#   4. Wait for CPU profile capture to finish
#   5. Fetch heap pprof (right after stress)
#   6. Fetch metrics and generate charts (cpu/heap call graphs)
#   7. Kill Tracee only after all above complete (if --stop-tracee)
#
# Output: metrics.txt, pprof-cpu.pprof, pprof-heap.pprof, cpu-graph.png/svg, heap-graph.png/svg
# Requires: curl, go tool pprof. For PNG charts: graphviz (dot). Falls back to SVG-only if missing.
#
# Usage: ./scripts/run-evt-stress-with-collection.sh --scenario NAME [options]
#   --scenario NAME       Scenario to run (required)
#   --events-file PATH    Suite YAML (default: docs/contributing/evt-suites/tracee-performance-gate.yaml)
#   --output-dir DIR     Artifacts output dir (default: ./artifacts-<scenario>)
#   --evt-binary PATH    Path to evt (default: ./dist/evt)
#   --profile-seconds N   CPU profile duration (default: 120, or PROFILE_SECONDS env)
#   --stop-tracee        Stop Tracee after collection (for running multiple scenarios)
#
# Requires: evt, tracee, evt-trigger-runner image, Docker. Run from repo root.
#

set -euo pipefail

readonly LOG_PREFIX="[run-evt-stress]"

log() {
    echo "${LOG_PREFIX}" "$@" >&2
}

# Retry helper: fetch_url RETRIES URL OUTPUT_FILE [CURL_EXTRA_ARGS...]
fetch_url() {
    local retries="$1"
    local url="$2"
    local out="$3"
    shift 3
    local i=0
    while [[ ${i} -lt ${retries} ]]; do
        if curl -sf --max-time 30 -o "${out}" "$@" "${url}"; then
            return 0
        fi
        i=$((i + 1))
        if [[ ${i} -lt ${retries} ]]; then
            log "Retry ${i}/${retries} for ${url}..."
            sleep 5
        fi
    done
    log "Failed to fetch ${url} after ${retries} attempts"
    return 1
}

SCENARIO=""
EVENTS_FILE="docs/contributing/evt-suites/tracee-performance-gate.yaml"
OUTPUT_DIR=""
EVT_BINARY="./dist/evt"
STOP_TRACEE=false
PROFILE_SECONDS=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --scenario)
            SCENARIO="$2"
            shift 2
            ;;
        --events-file)
            EVENTS_FILE="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --evt-binary)
            EVT_BINARY="$2"
            shift 2
            ;;
        --profile-seconds)
            PROFILE_SECONDS="$2"
            shift 2
            ;;
        --stop-tracee)
            STOP_TRACEE=true
            shift
            ;;
        -h | --help)
            sed -n '2,30p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *)
            log "Unknown option: $1"
            exit 1
            ;;
    esac
done

if [[ -z "${SCENARIO}" ]]; then
    log "Error: --scenario is required"
    exit 1
fi

: "${OUTPUT_DIR:=./artifacts-${SCENARIO}}"
mkdir -p "${OUTPUT_DIR}"

# Profile duration: CLI > env > default 120
: "${PROFILE_SECONDS:=120}"

LOG_FILE="${OUTPUT_DIR}/tracee-stress-${SCENARIO}.log"

log "Scenario: ${SCENARIO}"
log "Events file: ${EVENTS_FILE}"
log "Output dir: ${OUTPUT_DIR}"
log "Evt binary: ${EVT_BINARY}"
log "Profile duration: ${PROFILE_SECONDS}s"

PPROF_URL="http://localhost:3366/debug/pprof"
METRICS_URL="http://localhost:3366/metrics"

# 1. Start evt stress in background (evt starts Tracee, runs stress; --keep-tracee leaves it running)
log "Starting evt stress in background..."
"${EVT_BINARY}" stress \
    --events-file "${EVENTS_FILE}" \
    --scenario "${SCENARIO}" \
    --metrics --pprof \
    --tracee-output none \
    --keep-tracee \
    > "${LOG_FILE}" 2>&1 &
EVT_PID=$!

# 2. Wait for "Tracee is ready (PID: N)" in evt output, then start CPU profile capture in background
log "Waiting for Tracee ready message from evt..."
TRACEE_PID=""
while true; do
    if grep -q "Tracee is ready (PID:" "${LOG_FILE}" 2>/dev/null; then
        TRACEE_PID=$(grep "Tracee is ready (PID:" "${LOG_FILE}" 2>/dev/null | sed -n 's/.*Tracee is ready (PID: \([0-9]*\)).*/\1/p' | tail -1)
        if [[ -n "${TRACEE_PID}" ]]; then
            log "Tracee ready (PID: ${TRACEE_PID}). Starting CPU profile capture in background (${PROFILE_SECONDS}s)..."
            break
        fi
    fi
    sleep 1
    if ! kill -0 "${EVT_PID}" 2>/dev/null; then
        log "Error: evt exited before Tracee was ready. Check ${LOG_FILE}"
        exit 1
    fi
done

# Start CPU profile capture in background; it runs for PROFILE_SECONDS and rests until stress ends
curl -sf --max-time $((PROFILE_SECONDS + 60)) \
    "${PPROF_URL}/profile?seconds=${PROFILE_SECONDS}" \
    -o "${OUTPUT_DIR}/pprof-cpu.pprof" &
PROFILE_PID=$!

# 3. Wait for evt stress to finish
log "Waiting for evt stress to complete..."
if ! wait "${EVT_PID}"; then
    log "WARNING: evt exited with non-zero status. Check ${LOG_FILE}"
fi

# 4. Wait for CPU profile capture to finish
log "Waiting for CPU profile capture to finish..."
if ! wait "${PROFILE_PID}" 2>/dev/null; then
    log "WARNING: CPU profile capture may have failed"
fi

# 5. Fetch heap pprof (right after stress)
log "Fetching heap pprof..."
if ! curl -sf --max-time 30 -o "${OUTPUT_DIR}/pprof-heap.pprof" "${PPROF_URL}/heap"; then
    log "WARNING: Failed to fetch heap profile"
fi

# 6. Fetch metrics
log "Fetching metrics..."
if ! fetch_url 3 "${METRICS_URL}" "${OUTPUT_DIR}/metrics.txt"; then
    log "WARNING: Failed to fetch metrics"
fi

# 7. Generate charts (pprof -png/-svg produce call graphs, not flame graphs)
HAS_GRAPHVIZ=false
if command -v dot > /dev/null 2>&1; then
    HAS_GRAPHVIZ=true
fi

if [[ "${HAS_GRAPHVIZ}" == "true" ]]; then
    log "Generating cpu-graph.png..."
    if go tool pprof -png -output="${OUTPUT_DIR}/cpu-graph.png" "${OUTPUT_DIR}/pprof-cpu.pprof" 2> /dev/null; then
        log "  cpu-graph.png OK"
    else
        log "  cpu-graph.png failed, falling back to SVG only"
    fi
else
    log "graphviz not found, skipping PNG (CPU)"
fi

log "Generating cpu-graph.svg..."
if go tool pprof -svg -output="${OUTPUT_DIR}/cpu-graph.svg" "${OUTPUT_DIR}/pprof-cpu.pprof" 2> /dev/null; then
    log "  cpu-graph.svg OK"
else
    log "  cpu-graph.svg failed"
fi

if [[ "${HAS_GRAPHVIZ}" == "true" ]]; then
    log "Generating heap-graph.png..."
    if go tool pprof -png -output="${OUTPUT_DIR}/heap-graph.png" "${OUTPUT_DIR}/pprof-heap.pprof" 2> /dev/null; then
        log "  heap-graph.png OK"
    else
        log "  heap-graph.png failed, falling back to SVG only"
    fi
else
    log "graphviz not found, skipping PNG (heap)"
fi

log "Generating heap-graph.svg..."
if go tool pprof -svg -output="${OUTPUT_DIR}/heap-graph.svg" "${OUTPUT_DIR}/pprof-heap.pprof" 2> /dev/null; then
    log "  heap-graph.svg OK"
else
    log "  heap-graph.svg failed"
fi

# Surface trigger failures for visibility
if grep -q "exit code: 1\|Error:.*failed" "${LOG_FILE}" 2>/dev/null; then
    log "WARNING: Some triggers failed. Check ${LOG_FILE} for details:"
    grep -E "exit code: 1|Error:.*failed|Container logs:" "${LOG_FILE}" 2>/dev/null | head -20
fi

# 8. Kill Tracee only after stress, profile, heap capture, and charts are complete
if [[ "${STOP_TRACEE}" == "true" ]]; then
    log "Stopping Tracee (PID: ${TRACEE_PID})..."
    if [[ -n "${TRACEE_PID}" ]]; then
        sudo kill "${TRACEE_PID}" 2>/dev/null || sudo pkill -f "tracee" 2>/dev/null || true
    else
        sudo pkill -f "tracee" 2>/dev/null || true
    fi
    sleep 2
fi

log "Done. Artifacts in ${OUTPUT_DIR}/"

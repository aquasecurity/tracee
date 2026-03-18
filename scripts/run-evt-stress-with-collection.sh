#!/bin/bash
#
# Run evt stress with a scenario, collecting performance data during stress.
# Uses rolling pprof slices, OS resource sampling, and metrics scraping
# for workload-aligned profiling. Produces a gating-critical summary.json.
#
# Flow:
#   1. Start evt stress (evt prints "Tracee is ready (PID: N)" when ready)
#   2. On ready: start three background recorders:
#      a. OS resource sampler (1s intervals -> resource_timeseries.csv)
#      b. Metrics scraper (5s intervals -> metrics_timeseries.txt)
#      c. Rolling pprof slices (CPU + periodic heap/goroutine -> pprof/)
#   3. Wait for evt stress to finish
#   4. Signal recorders to stop via sentinel file, wait for completion
#   5. Post-collection: final heap, goroutine, metrics fetch
#   6. Merge CPU slices and generate charts (best-effort)
#   7. Compute KPIs and produce summary.json (gating-critical)
#   8. Write GitHub Actions Job Summary (or local fallback)
#   9. Kill Tracee only after all above complete (if --stop-tracee)
#
# Usage: ./scripts/run-evt-stress-with-collection.sh --scenario NAME [options]
#   --scenario NAME         Scenario to run (required)
#   --events-file PATH      Suite YAML (default: docs/.../tracee-performance-gate.yaml)
#   --output-dir DIR        Artifacts output dir (default: ./artifacts-<scenario>)
#   --evt-binary PATH       Path to evt (default: ./dist/evt)
#   --cpu-slice-seconds N   CPU profile slice duration (default: 10)
#   --baseline-dir DIR      Baseline dir (default: docs/.../baselines)
#   --stop-tracee           Stop Tracee after collection
#
# Requires: evt, tracee, curl, awk, go tool pprof. For PNG charts: graphviz.
#

set -euo pipefail

readonly LOG_PREFIX="[run-evt-stress]"

log() {
    echo "${LOG_PREFIX}" "$@" >&2
}

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

# Recorder A: OS resource sampler -- reads /proc/<pid> every 1s
start_os_sampler() {
    local tracee_pid="$1"
    local output_file="$2"
    local sentinel="$3"
    local clk_tck prev_ticks prev_epoch
    local now stat_line utime stime total_ticks cpu_pct dt dticks
    local rss_kb vsz_kb threads vol_cs nonvol_cs
    local status_content io_read io_write io_content

    clk_tck=$(getconf CLK_TCK)

    echo "timestamp,cpu_pct,rss_kb,vsz_kb,threads,io_read_bytes,io_write_bytes,voluntary_ctx_switches,nonvoluntary_ctx_switches" \
        > "${output_file}"

    prev_ticks=0
    prev_epoch=0

    while [[ ! -f "${sentinel}" ]]; do
        if [[ ! -d "/proc/${tracee_pid}" ]]; then
            log "OS sampler: process ${tracee_pid} gone, stopping"
            break
        fi

        now=$(date +%s)

        stat_line=$(sudo cat "/proc/${tracee_pid}/stat" 2> /dev/null) || break
        utime=$(echo "${stat_line}" | awk '{print $14}')
        stime=$(echo "${stat_line}" | awk '{print $15}')
        total_ticks=$((utime + stime))

        cpu_pct="0.0"
        if [[ ${prev_epoch} -gt 0 ]]; then
            dt=$((now - prev_epoch))
            if [[ ${dt} -gt 0 ]]; then
                dticks=$((total_ticks - prev_ticks))
                cpu_pct=$(awk "BEGIN {printf \"%.1f\", (${dticks} / ${clk_tck}) / ${dt} * 100}")
            fi
        fi
        prev_ticks=${total_ticks}
        prev_epoch=${now}

        rss_kb=0
        vsz_kb=0
        threads=0
        vol_cs=0
        nonvol_cs=0
        status_content=$(sudo cat "/proc/${tracee_pid}/status" 2> /dev/null) || break
        rss_kb=$(echo "${status_content}" | awk '/^VmRSS:/ {print $2}')
        vsz_kb=$(echo "${status_content}" | awk '/^VmSize:/ {print $2}')
        threads=$(echo "${status_content}" | awk '/^Threads:/ {print $2}')
        vol_cs=$(echo "${status_content}" | awk '/^voluntary_ctxt_switches:/ {print $2}')
        nonvol_cs=$(echo "${status_content}" | awk '/^nonvoluntary_ctxt_switches:/ {print $2}')
        : "${rss_kb:=0}"
        : "${vsz_kb:=0}"
        : "${threads:=0}"
        : "${vol_cs:=0}"
        : "${nonvol_cs:=0}"

        io_read=0
        io_write=0
        if io_content=$(sudo cat "/proc/${tracee_pid}/io" 2> /dev/null); then
            io_read=$(echo "${io_content}" | awk '/^read_bytes:/ {print $2}')
            io_write=$(echo "${io_content}" | awk '/^write_bytes:/ {print $2}')
        fi
        : "${io_read:=0}"
        : "${io_write:=0}"

        echo "${now},${cpu_pct},${rss_kb},${vsz_kb},${threads},${io_read},${io_write},${vol_cs},${nonvol_cs}" \
            >> "${output_file}"

        sleep 1
    done
}

# Recorder B: Metrics scraper -- curls /metrics every 5s
start_metrics_scraper() {
    local metrics_url="$1"
    local output_file="$2"
    local sentinel="$3"
    local s

    : > "${output_file}"

    while [[ ! -f "${sentinel}" ]]; do
        echo "--- $(date -u +%Y-%m-%dT%H:%M:%SZ) ---" >> "${output_file}"
        curl -sf --max-time 10 "${metrics_url}" >> "${output_file}" 2> /dev/null || true
        echo "" >> "${output_file}"

        s=0
        while [[ ${s} -lt 5 ]] && [[ ! -f "${sentinel}" ]]; do
            sleep 1
            ((s++))
        done
    done
}

# Recorder C: Rolling pprof -- CPU slices + periodic heap/goroutine
start_rolling_pprof() {
    local pprof_url="$1"
    local pprof_dir="$2"
    local sentinel="$3"
    local slice_seconds="$4"
    local slice_num padded max_time

    slice_num=0
    max_time=$((slice_seconds + 30))

    while [[ ! -f "${sentinel}" ]]; do
        slice_num=$((slice_num + 1))
        padded=$(printf "%04d" "${slice_num}")

        curl -sf --max-time "${max_time}" \
            "${pprof_url}/profile?seconds=${slice_seconds}" \
            -o "${pprof_dir}/cpu-slice-${padded}.pprof" 2> /dev/null || true

        if ((slice_num % 3 == 0)); then
            curl -sf --max-time 30 \
                "${pprof_url}/heap" \
                -o "${pprof_dir}/heap-${padded}.pprof" 2> /dev/null || true
            curl -sf --max-time 30 \
                "${pprof_url}/goroutine?debug=1" \
                -o "${pprof_dir}/goroutine-${padded}.txt" 2> /dev/null || true
        fi
    done
}

# Compute KPIs from resource_timeseries.csv and write summary.json.
# Sets SUMMARY_* globals so write_job_summary can consume them directly.
compute_summary() {
    local output_dir="$1"
    local stress_duration="$2"
    local csv_file="${output_dir}/resource_timeseries.csv"
    local summary_file="${output_dir}/summary.json"
    local io_read_first io_write_first io_read_last io_write_last

    SUMMARY_STRESS_DURATION="${stress_duration}"
    SUMMARY_PEAK_RSS=0
    SUMMARY_AVG_CPU="0.0"
    SUMMARY_P95_CPU="0.0"
    SUMMARY_IO_READ_TOTAL=0
    SUMMARY_IO_WRITE_TOTAL=0
    SUMMARY_SAMPLE_COUNT=0

    if [[ -f "${csv_file}" ]]; then
        SUMMARY_SAMPLE_COUNT=$(awk -F, 'NR > 1 {n++} END {print n+0}' "${csv_file}")

        if [[ ${SUMMARY_SAMPLE_COUNT} -gt 0 ]]; then
            SUMMARY_PEAK_RSS=$(awk -F, 'NR > 1 {if ($3+0 > max) max=$3+0} END {print max+0}' "${csv_file}")

            SUMMARY_AVG_CPU=$(awk -F, 'NR > 1 {sum+=$2; n++} END {if (n>0) printf "%.1f", sum/n; else print "0.0"}' "${csv_file}")

            SUMMARY_P95_CPU=$(awk -F, '
                NR > 1 {a[NR-1]=$2+0}
                END {
                    n=NR-1
                    if (n<=0) {print "0.0"; exit}
                    for (i=1;i<=n;i++)
                        for (j=i+1;j<=n;j++)
                            if (a[i]>a[j]) {t=a[i];a[i]=a[j];a[j]=t}
                    idx=int(n*0.95)
                    if (idx<1) idx=1
                    printf "%.1f", a[idx]
                }' "${csv_file}")

            io_read_first=$(awk -F, 'NR==2 {print $6+0}' "${csv_file}")
            io_write_first=$(awk -F, 'NR==2 {print $7+0}' "${csv_file}")
            io_read_last=$(awk -F, 'END {print $6+0}' "${csv_file}")
            io_write_last=$(awk -F, 'END {print $7+0}' "${csv_file}")

            SUMMARY_IO_READ_TOTAL=$((io_read_last - io_read_first))
            SUMMARY_IO_WRITE_TOTAL=$((io_write_last - io_write_first))
            if [[ ${SUMMARY_IO_READ_TOTAL} -lt 0 ]]; then SUMMARY_IO_READ_TOTAL=0; fi
            if [[ ${SUMMARY_IO_WRITE_TOTAL} -lt 0 ]]; then SUMMARY_IO_WRITE_TOTAL=0; fi
        fi
    fi

    SUMMARY_SLICES=$(($(find "${output_dir}/pprof" -name 'cpu-slice-*.pprof' 2> /dev/null | wc -l)))
    SUMMARY_HEAP_SNAPS=$(($(find "${output_dir}/pprof" -name 'heap-*.pprof' 2> /dev/null | wc -l)))
    if [[ -f "${output_dir}/pprof-heap-final.pprof" ]]; then
        SUMMARY_HEAP_SNAPS=$((SUMMARY_HEAP_SNAPS + 1))
    fi

    SUMMARY_CPU_STATUS="ok"
    if [[ ${SUMMARY_SLICES} -eq 0 ]]; then
        SUMMARY_CPU_STATUS="missing"
        log "WARNING: No CPU profile slices were collected"
    fi

    SUMMARY_COMMIT_SHA="${GITHUB_SHA:-$(git rev-parse HEAD 2> /dev/null || echo "unknown")}"
    SUMMARY_ARCH=$(uname -m)

    cat > "${summary_file}" << SUMMARY_EOF
{
  "stress_duration_seconds": ${SUMMARY_STRESS_DURATION},
  "peak_rss_kb": ${SUMMARY_PEAK_RSS},
  "avg_cpu_pct": ${SUMMARY_AVG_CPU},
  "p95_cpu_pct": ${SUMMARY_P95_CPU},
  "io_read_total_bytes": ${SUMMARY_IO_READ_TOTAL},
  "io_write_total_bytes": ${SUMMARY_IO_WRITE_TOTAL},
  "pprof_slices_collected": ${SUMMARY_SLICES},
  "heap_snapshots_collected": ${SUMMARY_HEAP_SNAPS},
  "commit_sha": "${SUMMARY_COMMIT_SHA}",
  "arch": "${SUMMARY_ARCH}",
  "cpu_profile_status": "${SUMMARY_CPU_STATUS}",
  "resource_samples_count": ${SUMMARY_SAMPLE_COUNT}
}
SUMMARY_EOF

    log "summary.json written: slices=${SUMMARY_SLICES}, heap=${SUMMARY_HEAP_SNAPS}, peak_rss=${SUMMARY_PEAK_RSS}kB, avg_cpu=${SUMMARY_AVG_CPU}%, p95_cpu=${SUMMARY_P95_CPU}%"
}

validate_summary() {
    local summary_file="$1"
    local field

    if [[ ! -f "${summary_file}" ]]; then
        log "ERROR: summary.json was not created"
        return 1
    fi

    if command -v python3 > /dev/null 2>&1; then
        if ! python3 -m json.tool "${summary_file}" > /dev/null 2>&1; then
            log "ERROR: summary.json is not valid JSON"
            return 1
        fi
    fi

    local -a required_fields=(
        stress_duration_seconds peak_rss_kb avg_cpu_pct p95_cpu_pct
        io_read_total_bytes io_write_total_bytes pprof_slices_collected
        heap_snapshots_collected commit_sha arch cpu_profile_status
    )
    for field in "${required_fields[@]}"; do
        if ! grep -q "\"${field}\"" "${summary_file}"; then
            log "ERROR: summary.json missing required field: ${field}"
            return 1
        fi
    done

    log "summary.json validation passed"
    return 0
}

# Regression tolerance: percentage above baseline that triggers failure
readonly REGRESSION_TOLERANCE_PEAK_RSS=20
readonly REGRESSION_TOLERANCE_AVG_CPU=25
readonly REGRESSION_TOLERANCE_P95_CPU=25

# Extract a numeric value from a simple JSON file by field name
json_field() {
    local file="$1"
    local field="$2"
    grep "\"${field}\"" "${file}" | head -1 | sed 's/.*: *//; s/[",]//g; s/ *$//'
}

# Compare current run against a checked-in baseline.
# Returns 0 (pass) or 1 (regression detected).
# Sets BASELINE_RESULT for job summary consumption.
compare_baseline() {
    local baseline_file="$1"
    local regressions=0
    local bl_peak_rss bl_avg_cpu bl_p95_cpu
    local max_rss max_avg_cpu max_p95_cpu

    BASELINE_RESULT="skipped"

    if [[ ! -f "${baseline_file}" ]]; then
        log "WARNING: No baseline file found at ${baseline_file} -- skipping comparison"
        return 0
    fi

    bl_peak_rss=$(json_field "${baseline_file}" "peak_rss_kb")
    bl_avg_cpu=$(json_field "${baseline_file}" "avg_cpu_pct")
    bl_p95_cpu=$(json_field "${baseline_file}" "p95_cpu_pct")

    if [[ -z "${bl_peak_rss}" ]] || [[ -z "${bl_avg_cpu}" ]] || [[ -z "${bl_p95_cpu}" ]]; then
        log "WARNING: Baseline file is missing required fields -- skipping comparison"
        return 0
    fi

    log "Comparing against baseline: peak_rss=${bl_peak_rss}kB, avg_cpu=${bl_avg_cpu}%, p95_cpu=${bl_p95_cpu}%"

    BASELINE_PEAK_RSS="${bl_peak_rss}"
    BASELINE_AVG_CPU="${bl_avg_cpu}"
    BASELINE_P95_CPU="${bl_p95_cpu}"

    # peak_rss_kb check
    if [[ ${bl_peak_rss} -gt 0 ]]; then
        max_rss=$(awk "BEGIN {printf \"%.0f\", ${bl_peak_rss} * (1 + ${REGRESSION_TOLERANCE_PEAK_RSS} / 100)}")
        if awk "BEGIN {exit !(${SUMMARY_PEAK_RSS} > ${max_rss})}"; then
            log "REGRESSION: peak_rss_kb: current=${SUMMARY_PEAK_RSS}, baseline=${bl_peak_rss}, max_allowed=${max_rss} (+${REGRESSION_TOLERANCE_PEAK_RSS}%)"
            ((regressions++))
        fi
    fi

    # avg_cpu_pct check
    max_avg_cpu=$(awk "BEGIN {printf \"%.1f\", ${bl_avg_cpu} * (1 + ${REGRESSION_TOLERANCE_AVG_CPU} / 100)}")
    if awk "BEGIN {exit !(${SUMMARY_AVG_CPU} > ${max_avg_cpu})}"; then
        log "REGRESSION: avg_cpu_pct: current=${SUMMARY_AVG_CPU}, baseline=${bl_avg_cpu}, max_allowed=${max_avg_cpu} (+${REGRESSION_TOLERANCE_AVG_CPU}%)"
        ((regressions++))
    fi

    # p95_cpu_pct check
    max_p95_cpu=$(awk "BEGIN {printf \"%.1f\", ${bl_p95_cpu} * (1 + ${REGRESSION_TOLERANCE_P95_CPU} / 100)}")
    if awk "BEGIN {exit !(${SUMMARY_P95_CPU} > ${max_p95_cpu})}"; then
        log "REGRESSION: p95_cpu_pct: current=${SUMMARY_P95_CPU}, baseline=${bl_p95_cpu}, max_allowed=${max_p95_cpu} (+${REGRESSION_TOLERANCE_P95_CPU}%)"
        ((regressions++))
    fi

    if [[ ${regressions} -gt 0 ]]; then
        BASELINE_RESULT="failed"
        log "REGRESSION DETECTED: ${regressions} metric(s) exceeded baseline tolerance"
        return 1
    fi

    BASELINE_RESULT="passed"
    log "Baseline comparison passed -- no regressions detected"
    return 0
}

write_job_summary() {
    local scenario="$1"
    local md=""

    md+="### Performance Gate: ${scenario} (${SUMMARY_ARCH})"$'\n'
    md+=$'\n'
    md+="| Metric | Value |"$'\n'
    md+="| --- | --- |"$'\n'
    md+="| Stress Duration | ${SUMMARY_STRESS_DURATION}s |"$'\n'
    md+="| Peak RSS | ${SUMMARY_PEAK_RSS} kB |"$'\n'
    md+="| Avg CPU | ${SUMMARY_AVG_CPU}% |"$'\n'
    md+="| P95 CPU | ${SUMMARY_P95_CPU}% |"$'\n'
    md+="| IO Read Total | ${SUMMARY_IO_READ_TOTAL} bytes |"$'\n'
    md+="| IO Write Total | ${SUMMARY_IO_WRITE_TOTAL} bytes |"$'\n'
    md+="| CPU Slices | ${SUMMARY_SLICES} |"$'\n'
    md+="| Heap Snapshots | ${SUMMARY_HEAP_SNAPS} |"$'\n'
    md+="| CPU Profile Status | ${SUMMARY_CPU_STATUS} |"$'\n'
    md+="| Baseline Comparison | ${BASELINE_RESULT} |"$'\n'
    md+="| Commit | \`${SUMMARY_COMMIT_SHA}\` |"$'\n'

    if [[ "${BASELINE_RESULT}" == "failed" ]]; then
        md+=$'\n'
        md+="**Regression details:**"$'\n'
        md+=$'\n'
        md+="| Metric | Current | Baseline | Max Allowed |"$'\n'
        md+="| --- | --- | --- | --- |"$'\n'
        md+="| Peak RSS (kB) | ${SUMMARY_PEAK_RSS} | ${BASELINE_PEAK_RSS} | +${REGRESSION_TOLERANCE_PEAK_RSS}% |"$'\n'
        md+="| Avg CPU (%) | ${SUMMARY_AVG_CPU} | ${BASELINE_AVG_CPU} | +${REGRESSION_TOLERANCE_AVG_CPU}% |"$'\n'
        md+="| P95 CPU (%) | ${SUMMARY_P95_CPU} | ${BASELINE_P95_CPU} | +${REGRESSION_TOLERANCE_P95_CPU}% |"$'\n'
    fi

    if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
        echo "${md}" >> "${GITHUB_STEP_SUMMARY}"
        log "Job Summary written to GITHUB_STEP_SUMMARY"
    else
        log "Job Summary (local):"
        echo "${md}" >&2
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

SCENARIO=""
EVENTS_FILE="docs/contributing/evt-suites/tracee-performance-gate.yaml"
OUTPUT_DIR=""
EVT_BINARY="./dist/evt"
STOP_TRACEE=false
CPU_SLICE_SECONDS=10
BASELINE_DIR="docs/contributing/evt-suites/baselines"

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
        --cpu-slice-seconds)
            CPU_SLICE_SECONDS="$2"
            shift 2
            ;;
        --baseline-dir)
            BASELINE_DIR="$2"
            shift 2
            ;;
        --stop-tracee)
            STOP_TRACEE=true
            shift
            ;;
        -h | --help)
            sed -n '2,31p' "$0" | sed 's/^# \?//'
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
mkdir -p "${OUTPUT_DIR}/pprof"

LOG_FILE="${OUTPUT_DIR}/tracee-stress-${SCENARIO}.log"
SENTINEL="${OUTPUT_DIR}/.stop_sampling"
rm -f "${SENTINEL}"

TRACEE_PID=""

cleanup() {
    rm -f "${SENTINEL}" 2> /dev/null || true
    if [[ "${STOP_TRACEE}" == "true" ]] && [[ -n "${TRACEE_PID}" ]]; then
        sudo kill "${TRACEE_PID}" 2> /dev/null || true
        wait "${TRACEE_PID}" 2> /dev/null || true
        TRACEE_PID=""
    fi
}
trap cleanup EXIT

log "Scenario: ${SCENARIO}"
log "Events file: ${EVENTS_FILE}"
log "Output dir: ${OUTPUT_DIR}"
log "Evt binary: ${EVT_BINARY}"
log "CPU slice duration: ${CPU_SLICE_SECONDS}s"

PPROF_URL="http://localhost:3366/debug/pprof"
METRICS_URL="http://localhost:3366/metrics"

# 1. Start evt stress in background
log "Starting evt stress in background..."
"${EVT_BINARY}" stress \
    --events-file "${EVENTS_FILE}" \
    --scenario "${SCENARIO}" \
    --metrics --pprof \
    --tracee-output none \
    --keep-tracee \
    > "${LOG_FILE}" 2>&1 &
EVT_PID=$!

# 2. Wait for Tracee ready
log "Waiting for Tracee ready message from evt..."
while true; do
    if grep -q "Tracee is ready (PID:" "${LOG_FILE}" 2> /dev/null; then
        TRACEE_PID=$(grep "Tracee is ready (PID:" "${LOG_FILE}" 2> /dev/null \
            | sed -n 's/.*Tracee is ready (PID: \([0-9]*\)).*/\1/p' | tail -1)
        if [[ -n "${TRACEE_PID}" ]]; then
            log "Tracee ready (PID: ${TRACEE_PID})"
            break
        fi
    fi
    sleep 1
    if ! kill -0 "${EVT_PID}" 2> /dev/null; then
        log "Error: evt exited before Tracee was ready. Check ${LOG_FILE}"
        exit 1
    fi
done

# 3. Start background recorders
STRESS_START=$(date +%s)

log "Starting OS resource sampler..."
start_os_sampler "${TRACEE_PID}" "${OUTPUT_DIR}/resource_timeseries.csv" "${SENTINEL}" &
SAMPLER_PID=$!

log "Starting metrics scraper..."
start_metrics_scraper "${METRICS_URL}" "${OUTPUT_DIR}/metrics_timeseries.txt" "${SENTINEL}" &
SCRAPER_PID=$!

log "Starting rolling pprof collector (${CPU_SLICE_SECONDS}s slices)..."
start_rolling_pprof "${PPROF_URL}" "${OUTPUT_DIR}/pprof" "${SENTINEL}" "${CPU_SLICE_SECONDS}" &
PPROF_PID=$!

# 4. Wait for evt stress to finish
log "Waiting for evt stress to complete..."
EVT_EXIT=0
if ! wait "${EVT_PID}"; then
    EVT_EXIT=$?
    log "WARNING: evt exited with status ${EVT_EXIT}. Check ${LOG_FILE}"
fi

STRESS_END=$(date +%s)
STRESS_DURATION=$((STRESS_END - STRESS_START))
log "Stress completed in ${STRESS_DURATION}s"

# 5. Signal recorders to stop and wait for each
log "Signaling recorders to stop..."
touch "${SENTINEL}"

RECORDER_WARNINGS=0
if ! wait "${SAMPLER_PID}" 2> /dev/null; then
    log "WARNING: OS sampler exited with non-zero status"
    ((RECORDER_WARNINGS++)) || true
fi
if ! wait "${SCRAPER_PID}" 2> /dev/null; then
    log "WARNING: Metrics scraper exited with non-zero status"
    ((RECORDER_WARNINGS++)) || true
fi
if ! wait "${PPROF_PID}" 2> /dev/null; then
    log "WARNING: Rolling pprof exited with non-zero status"
    ((RECORDER_WARNINGS++)) || true
fi
log "Recorders stopped (${RECORDER_WARNINGS} warnings)"

# 6. Post-collection: final snapshots while Tracee is still running
log "Post-collection: fetching final snapshots..."

if ! curl -sf --max-time 30 -o "${OUTPUT_DIR}/pprof-heap-final.pprof" \
    "${PPROF_URL}/heap" 2> /dev/null; then
    log "WARNING: Failed to fetch final heap profile"
fi

if ! curl -sf --max-time 30 -o "${OUTPUT_DIR}/pprof/goroutine-final.txt" \
    "${PPROF_URL}/goroutine?debug=1" 2> /dev/null; then
    log "WARNING: Failed to fetch final goroutine profile"
fi

if ! fetch_url 3 "${METRICS_URL}" "${OUTPUT_DIR}/metrics-final.txt"; then
    log "WARNING: Failed to fetch final metrics"
fi

# 7. Merge CPU slices (if any exist)
SLICE_COUNT=$(($(find "${OUTPUT_DIR}/pprof" -name 'cpu-slice-*.pprof' 2> /dev/null | wc -l)))
if [[ ${SLICE_COUNT} -gt 0 ]]; then
    log "Merging ${SLICE_COUNT} CPU profile slices..."
    # shellcheck disable=SC2046
    if ! go tool pprof -proto \
        $(find "${OUTPUT_DIR}/pprof" -name 'cpu-slice-*.pprof' | sort) \
        > "${OUTPUT_DIR}/pprof-cpu-merged.pprof" 2> /dev/null; then
        log "WARNING: CPU slice merge failed"
    fi
else
    log "WARNING: No CPU slices collected, skipping merge"
fi

# 8. Generate charts (best-effort)
HAS_GRAPHVIZ=false
if command -v dot > /dev/null 2>&1; then
    HAS_GRAPHVIZ=true
fi

if [[ -f "${OUTPUT_DIR}/pprof-cpu-merged.pprof" ]]; then
    if [[ "${HAS_GRAPHVIZ}" == "true" ]]; then
        log "Generating cpu-graph.png..."
        if go tool pprof -png -output="${OUTPUT_DIR}/cpu-graph.png" \
            "${OUTPUT_DIR}/pprof-cpu-merged.pprof" 2> /dev/null; then
            log "  cpu-graph.png OK"
        else
            log "  cpu-graph.png failed, falling back to SVG only"
        fi
    fi
    log "Generating cpu-graph.svg..."
    if go tool pprof -svg -output="${OUTPUT_DIR}/cpu-graph.svg" \
        "${OUTPUT_DIR}/pprof-cpu-merged.pprof" 2> /dev/null; then
        log "  cpu-graph.svg OK"
    else
        log "  cpu-graph.svg failed"
    fi
fi

if [[ -f "${OUTPUT_DIR}/pprof-heap-final.pprof" ]]; then
    if [[ "${HAS_GRAPHVIZ}" == "true" ]]; then
        log "Generating heap-graph.png..."
        if go tool pprof -png -output="${OUTPUT_DIR}/heap-graph.png" \
            "${OUTPUT_DIR}/pprof-heap-final.pprof" 2> /dev/null; then
            log "  heap-graph.png OK"
        else
            log "  heap-graph.png failed, falling back to SVG only"
        fi
    fi
    log "Generating heap-graph.svg..."
    if go tool pprof -svg -output="${OUTPUT_DIR}/heap-graph.svg" \
        "${OUTPUT_DIR}/pprof-heap-final.pprof" 2> /dev/null; then
        log "  heap-graph.svg OK"
    else
        log "  heap-graph.svg failed"
    fi
fi

# 9. Compute KPIs and generate summary.json (gating-critical)
log "Computing KPIs and generating summary.json..."
compute_summary "${OUTPUT_DIR}" "${STRESS_DURATION}"

if ! validate_summary "${OUTPUT_DIR}/summary.json"; then
    log "FATAL: summary.json validation failed -- gating-critical output is invalid"
    exit 1
fi

# 10. Compare against baseline (regression detection)
BASELINE_FILE="${BASELINE_DIR}/$(uname -m)-${SCENARIO}.json"
BASELINE_RESULT="skipped"
BASELINE_PEAK_RSS="n/a"
BASELINE_AVG_CPU="n/a"
BASELINE_P95_CPU="n/a"
GATE_REGRESSION=0
if ! compare_baseline "${BASELINE_FILE}"; then
    GATE_REGRESSION=1
fi

# 11. Write Job Summary (includes regression details if any)
write_job_summary "${SCENARIO}"

if [[ ${GATE_REGRESSION} -ne 0 ]]; then
    log "FATAL: Performance regression detected -- gate failed"
    exit 1
fi

# Surface trigger failures for visibility
if grep -q "exit code: 1\|Error:.*failed" "${LOG_FILE}" 2> /dev/null; then
    log "WARNING: Some triggers failed. Check ${LOG_FILE} for details:"
    grep -E "exit code: 1|Error:.*failed|Container logs:" "${LOG_FILE}" 2> /dev/null | head -20
fi

# 11. Kill Tracee (if --stop-tracee); also handled by cleanup trap on early exit.
# We must wait for the killed process so the shell reaps it cleanly (otherwise
# the shell exits with 143/SIGTERM from the unkilled child).
if [[ "${STOP_TRACEE}" == "true" ]]; then
    log "Stopping Tracee (PID: ${TRACEE_PID})..."
    if [[ -n "${TRACEE_PID}" ]]; then
        sudo kill "${TRACEE_PID}" 2> /dev/null || sudo pkill -f "tracee" 2> /dev/null || true
        wait "${TRACEE_PID}" 2> /dev/null || true
    else
        sudo pkill -f "tracee" 2> /dev/null || true
    fi
    TRACEE_PID=""
    sleep 2
fi

rm -f "${SENTINEL}"
log "Done. Artifacts in ${OUTPUT_DIR}/"

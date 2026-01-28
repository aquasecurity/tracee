#!/bin/bash

# WRITABLE_DATA_STORE e2e test: builds and runs ds_writer, which writes to the writable
# data store via DataStoreService gRPC. The E2eWritableStore detector looks for key "bruh"
# value "moment" on sched_process_exit (comm=ds_writer).

exit_err() {
    echo -n "ERROR: "
    echo "$@"
    exit 1
}

info() {
    echo -n "INFO: "
    echo "$@"
}

# Parse command line arguments
BUILD=false
RUN=true

while [[ $# -gt 0 ]]; do
    case $1 in
        --build)
            BUILD=true
            RUN=false
            shift
            ;;
        --run)
            RUN=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--build] [--run]"
            exit 1
            ;;
    esac
done

# Build phase: build ds_writer
if [[ "${BUILD}" == "true" ]]; then
    info "building ds_writer for writable data store test..."
    go build -o ./tests/e2e/core/scripts/ds_writer/ds_writer ./tests/e2e/core/scripts/ds_writer || exit_err "could not build ds_writer"
fi

# Run phase: execute ds_writer processes
if [[ "${RUN}" == "true" ]]; then
    # Run ds_writer 4 times in parallel. Each instance writes 1000 key/value pairs
    # then the final "bruh"/"moment"; the E2eWritableStore detector matches on that.
    # 
    # Expected detection count: 16-40 events (typically ~25)
    # - 4 processes run in parallel
    # - Each Go process spawns multiple OS threads (main + GOMAXPROCS workers + GC + network)
    # - Detector fires on sched_process_exit for comm=ds_writer when store has "bruh"="moment"
    # - Thread count varies by CPU count, Go runtime, and gRPC library behavior
    # - Early thread exits may not match if "bruh" not written yet (race condition)
    declare -A pids=()

    for i in {1..4}; do
        ./tests/e2e/core/scripts/ds_writer/ds_writer -key "bruh" -value "moment" &
        pids["${i}"]=$!
    done

    for i in "${!pids[@]}"; do
        wait "${pids[${i}]}" || exit_err "ds_writer process ${i} failed"
        info "ds_writer process ${i} completed"
    done
fi

#!/bin/bash

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

# Build phase: build the Go program
if [[ "${BUILD}" == "true" ]]; then
    info "building ds_writer..."
    go build -o ./tests/e2e-inst-signatures/scripts/ds_writer/ds_writer tests/e2e-inst-signatures/scripts/ds_writer/*.go || exit_err "could not build ds_writer"
fi

# Run phase: execute ds_writer processes
if [[ "${RUN}" == "true" ]]; then
    # run the ds_writer 4 times in parallel
    # each instance pollutes with a stream of a 1000 key values, then writes the given input
    # the signature searches for this final input
    declare -A pids=()
    
    for i in {1..4}; do
        ./tests/e2e-inst-signatures/scripts/ds_writer/ds_writer -key "bruh" -value "moment" &
        pids["${i}"]=$!
    done

    # Wait for all background processes to complete
    for i in "${!pids[@]}"; do
        wait "${pids[${i}]}" || exit_err "ds_writer process ${i} failed"
        info "ds_writer process ${i} completed"
    done
fi

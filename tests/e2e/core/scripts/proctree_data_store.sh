#!/usr/bin/bash

exit_err() {
    echo -n "ERROR: "
    echo "$@"
    exit 1
}

info() {
    echo -n "INFO: "
    echo "$@"
}

prog="proctreetester"
dir="tests/e2e/core/scripts"

# Parse command line arguments
BUILD="false"
RUN="true"

while [[ $# -gt 0 ]]; do
    case $1 in
        --build)
            BUILD="true"
            RUN="false"
            shift
            ;;
        --run)
            RUN="true"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--build] [--run]"
            exit 1
            ;;
    esac
done

# Build phase: compile the program
if [[ "${BUILD}" == "true" ]]; then
    info "compiling ${prog}..."
    gcc "${dir}/${prog}.c" -o "${dir}/${prog}" -lpthread || exit_err "could not compile ${prog}.c"
fi

# Run phase: execute the program
if [[ "${RUN}" == "true" ]]; then
    # Formula: f(n) = 1 + n × f(n-1), where f(0) = 1
    # TIMES=0 creates 1 PROCTREE_DATA_STORE event
    # TIMES=1 creates 2 PROCTREE_DATA_STORE events
    # TIMES=2 creates 5 PROCTREE_DATA_STORE events
    # TIMES=3 creates 16 PROCTREE_DATA_STORE events
    # TIMES=4 creates 65 PROCTREE_DATA_STORE events
    # TIMES=5 might case some missing ppids and/or lineage issues in github runners
    TIMES=3 \
    E2E_INST_TEST_SLEEP="${E2E_INST_TEST_SLEEP:-10}" \
        "./${dir}/${prog}" || exit_err "could not run ${prog}"
fi

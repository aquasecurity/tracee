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

output_file="vfs_writev.txt"
prog="writev"
dir="tests/e2e/core/scripts/writev_tester"

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

# Build phase: compile the program
if [[ "${BUILD}" == "true" ]]; then
    info "compiling ${prog}..."
    gcc "${dir}/${prog}.c" -o "${dir}/${prog}" -lpthread || exit_err "could not compile ${prog}.c"
fi

# Run phase: execute the program
if [[ "${RUN}" == "true" ]]; then
    "./${dir}/${prog}" > /dev/null
    rm -f "${output_file}"
    rm -f "${dir}/${prog}"
fi

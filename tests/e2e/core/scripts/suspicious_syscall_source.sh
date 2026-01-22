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

prog=sys_src_tester
dir=tests/e2e/core/scripts

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
    gcc "${dir}/${prog}.c" -pthread -o "${dir}/${prog}" -z execstack || exit_err "could not compile ${prog}.c"
fi

# Run phase: execute the program with different arguments
if [[ "$RUN" == "true" ]]; then
    info "running ${prog} stack mode..."
    "./${dir}/${prog}" stack || exit_err "${prog} stack mode failed"
    
    info "running ${prog} heap mode..."
    "./${dir}/${prog}" heap || exit_err "${prog} heap mode failed"
    
    info "running ${prog} mmap mode..."
    "./${dir}/${prog}" mmap || exit_err "${prog} mmap mode failed"
    
    info "running ${prog} thread-stack mode..."
    "./${dir}/${prog}" thread-stack || exit_err "${prog} thread-stack mode failed"
    
    info "all modes succeeded"
fi

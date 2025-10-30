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

BUSYBOX_IMAGE="busybox:1.37.0"
wait_container=${E2E_INST_TEST_SLEEP:-5} # time to let container alive

# Parse command line arguments
INSTALL=false
RUN=true

while [[ $# -gt 0 ]]; do
    case $1 in
        --install)
            INSTALL=true
            RUN=false
            shift
            ;;
        --run)
            RUN=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--install] [--run]"
            exit 1
            ;;
    esac
done

# Install phase: pull Docker image
if [[ "$INSTALL" == "true" ]]; then
    docker image pull "${BUSYBOX_IMAGE}" > /dev/null 2>&1 || {
        exit_err "failed to pull container image"
    }
fi

# Run phase: execute container
if [[ "$RUN" == "true" ]]; then
    # capture container output and print it using info
    container_output=$(docker container run --rm "${BUSYBOX_IMAGE}" /bin/sh -c "
        \$(which ls) > /dev/null &&
        echo \"inside the container...\" &&
        echo \"\$(which ls) executed successfully inside container...\" &&
        echo \"sleeping for ${wait_container} seconds...\" &&
        sleep ${wait_container}
    " 2>&1)

    while IFS= read -r line; do
        info "${line}"
    done <<< "${container_output}"
fi

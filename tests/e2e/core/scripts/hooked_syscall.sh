#!/usr/bin/bash -e

exit_err() {
    echo -n "ERROR: "
    echo "$@"
    exit 1
}

info() {
    echo -n "INFO: "
    echo "$@"
}

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  --build     Build the kernel module"
    echo "  --install   Install and trigger the module"
    echo "  --uninstall Uninstall the module"
    echo "  --help      Show this help message"
    echo ""
    echo "If no options are provided, both build and install are performed."
}

# Parse command line arguments
BUILD=false
INSTALL=false
UNINSTALL=false

if [[ $# -eq 0 ]]; then
    # Default behavior: build and install but don't uninstall
    BUILD=true
    INSTALL=true
    UNINSTALL=false
else
    while [[ $# -gt 0 ]]; do
        case $1 in
            --build)
                BUILD=true
                shift
                ;;
            --install)
                INSTALL=true
                shift
                ;;
            --uninstall)
                UNINSTALL=true
                shift
                ;;
            --help)
                usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
fi

dir="tests/e2e/core/scripts/hijack"
cd $dir || exit_err "could not cd to $dir"

if [[ "$BUILD" == "true" ]]; then
    info "building syscall hijack module..."
    make clean && make || exit_err "could not build module"
fi

if [[ "$INSTALL" == "true" ]]; then
    if lsmod | grep -q hijack; then
        if [[ "${BUILD}" == "false" ]]; then
            info "hijack module already loaded, skipping installation"
            exit 0
        fi

        info "hijack module already loaded, unloading to install new version..."
        ./unload.sh || exit_err "could not unload hijack module"
    fi

    ./load.sh || exit_err "could not load module"

    # Sleep a bit to allow module to load
    sleep_time=${E2E_INST_TEST_SLEEP:-5}
    sleep "${sleep_time}"
    lsmod | grep -q hijack > /dev/null || exit_err "hijack module not loaded"
fi

if [[ "${UNINSTALL}" == "true" ]]; then
    ./unload.sh || exit_err "could not unload hijack module"
fi

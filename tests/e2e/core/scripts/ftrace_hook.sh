#!/usr/bin/bash -e

exit_err() {
    echo -n "ERROR: "
    echo "$@"
    exit 1
}

error() {
    echo -n "ERROR: "
    echo "$@"
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

dir="tests/e2e/core/scripts/hooker"
cd $dir || exit_err "could not cd to $dir"

if [[ "$BUILD" == "true" ]]; then
    info "Building ftrace hook module..."
    make clean && make || exit_err "could not build ftrace hook module"
fi

if [[ "$INSTALL" == "true" ]]; then
    if lsmod | grep -q hooker; then
        if [[ "${BUILD}" == "false" ]]; then
            info "ftrace hook module already loaded, skipping installation"
            exit 0
        fi

        info "ftrace hook module already loaded, unloading to install new version..."
        ./unload.sh || exit_err "could not unload ftrace hook module"
    fi

    ./load.sh || exit_err "could not load ftrace hook module"

    # Sleep a bit to allow module to load
    sleep_time=${E2E_INST_TEST_SLEEP:-5}
    sleep "${sleep_time}"
    lsmod | grep hooker > /dev/null || exit_err "ftrace hook module not loaded"

    # Trigger commit_creds function call
    sudo true > /dev/null 2>&1

    # Check kernel messages for hook confirmation
    dmesg | tail -10 | grep -q "hooker: commit_creds() intercepted!" || {
        error "no ftrace hook kernel messages found"
    }
fi

if [[ "$UNINSTALL" == "true" ]]; then
    ./unload.sh || exit_err "could not unload ftrace hook module"
fi

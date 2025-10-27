#!/usr/bin/bash -e

KERNEL_VERSION=$(uname -r)

exit_err() {
    echo -n "ERROR: "
    echo "$@"
    exit 1
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

. /etc/os-release

dir="tests/e2e-inst-signatures/scripts/hijack"
cd $dir || exit_err "could not cd to $dir"

if [[ "$BUILD" == "true" ]]; then
    echo "Building syscall hijack module..."
    make clean && make || exit_err "could not build module"
fi

if [[ "$INSTALL" == "true" ]]; then
    if lsmod | grep -q hijack; then
        if [[ "${BUILD}" == "false" ]]; then
            echo "hijack module already loaded, skipping installation"
            exit 0
        fi

        echo "hijack module already loaded, unloading to install new version..."
        ./unload.sh || exit_err "could not unload module"
    fi

    echo "Installing syscall hijack module..."
    ./load.sh || exit_err "could not load module"
    
    # Sleep a bit to allow module to load
    sleep 5
    lsmod | grep hijack || exit_err "module not loaded"
    echo "Module loaded and triggered successfully"
fi

if [[ "$UNINSTALL" == "true" ]]; then
    echo "Uninstalling syscall hijack module..."
    ./unload.sh || exit_err "could not unload module"
fi

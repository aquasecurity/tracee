#!/bin/bash
#
# Tracee VM Test Wrapper (runs on host)
#
# This script orchestrates the complete test execution lifecycle:
# 1. Validates prerequisites (Vagrant, hypervisor)
# 2. Starts a test VM using VM_TYPE=test
# 3. Executes tests inside the VM
# 4. Handles cleanup (destroy on success, preserve on failure)
#
# Usage: ./tests/run-vm-tests.sh [OPTIONS]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TRACEE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VM_NAME="tracee-test-vm"

# Default configuration (can be overridden by env vars)
: "${VM_TYPE:=test}"
: "${VM_CPUS:=4}"
: "${VM_MEM:=8}"
: "${KEEP_VM_ON_SUCCESS:=false}"

# Test selection flags (will be passed to in-VM script)
TEST_ARGS=()

# Logging functions
info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# Show usage
show_usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Run Tracee tests in an isolated Vagrant VM environment.

Options:
  --keep-vm         Keep VM running even on success (for debugging)
  --vm-cpus NUM     Number of CPU cores (default: 4)
  --vm-mem GB       Memory in GB (default: 8)
  --unit            Run only unit tests
  --integration     Run only integration tests
  --e2e-inst        Run only e2e instrumentation tests
  --e2e-net         Run only e2e network tests
  --help, -h        Show this help message

Environment Variables:
  VM_CPUS           Number of CPU cores (default: 4)
  VM_MEM            Memory in GB (default: 8)
  KEEP_VM_ON_SUCCESS Keep VM even on success (default: false)

Test Selection:
  Multiple test options can be combined. If no test options are specified,
  all tests will run.

Examples:
  # Run with defaults (4 CPUs, 8GB RAM, all tests)
  ./tests/run-vm-tests.sh

  # Use more resources
  VM_CPUS=8 VM_MEM=16 ./tests/run-vm-tests.sh

  # Keep VM for debugging even on success
  ./tests/run-vm-tests.sh --keep-vm

  # Run only integration tests
  ./tests/run-vm-tests.sh --integration

  # Run unit and integration tests only
  ./tests/run-vm-tests.sh --unit --integration

EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --keep-vm)
                KEEP_VM_ON_SUCCESS=true
                shift
                ;;
            --vm-cpus)
                VM_CPUS="$2"
                shift 2
                ;;
            --vm-mem)
                VM_MEM="$2"
                shift 2
                ;;
            --unit|--integration|--e2e-inst|--e2e-net)
                # Collect test selection flags
                TEST_ARGS+=("$1")
                shift
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

# Check prerequisites
check_prerequisites() {
    info "Checking prerequisites..."

    # Check if vagrant is installed
    if ! command -v vagrant &> /dev/null; then
        error "Vagrant is not installed"
        error "Please install Vagrant: https://www.vagrantup.com/downloads"
        return 1
    fi

    # Check if we're in the tracee directory
    if [[ ! -f "${TRACEE_ROOT}/Vagrantfile" ]]; then
        error "Vagrantfile not found in ${TRACEE_ROOT}"
        error "Please run this script from the Tracee repository"
        return 1
    fi

    # Check for VirtualBox or Parallels
    local has_hypervisor=false
    if command -v VBoxManage &> /dev/null; then
        info "Found VirtualBox"
        has_hypervisor=true
    elif command -v prlctl &> /dev/null; then
        info "Found Parallels"
        has_hypervisor=true
    fi

    if [[ "$has_hypervisor" == "false" ]]; then
        warn "No hypervisor detected (VirtualBox or Parallels)"
        warn "Please ensure you have a Vagrant-compatible hypervisor installed"
    fi

    success "Prerequisites check passed"
    return 0
}

# Start the VM
start_vm() {
    info "Starting VM: ${VM_NAME}"
    info "Configuration: ${VM_CPUS} CPUs, ${VM_MEM}GB RAM"

    cd "${TRACEE_ROOT}"

    # Check if any other Tracee VM is running
    if vagrant status 2>/dev/null | grep -E "tracee-(dev|test)-vm.*running" | grep -v "${VM_NAME}" > /dev/null; then
        warn "Another Tracee VM is running. Stopping it first..."
        vagrant halt
        sleep 2
    fi

    # Export configuration
    export VM_TYPE="${VM_TYPE}"
    export VM_CPUS="${VM_CPUS}"
    export VM_MEM="${VM_MEM}"

    # Start the VM
    info "Running: vagrant up..."
    info "(This may take several minutes on first run)"

    if vagrant up; then
        success "VM started successfully"
        return 0
    else
        error "Failed to start VM"
        return 1
    fi
}

# Check if VM is running
is_vm_running() {
    cd "${TRACEE_ROOT}"
    vagrant status "${VM_NAME}" 2>/dev/null | grep -q "running"
}

# Run tests in the VM
run_tests_in_vm() {
    info "Executing tests inside VM..."

    cd "${TRACEE_ROOT}"

    # Copy script to /tmp to avoid 9p filesystem and ssh.extra_args issues
    info "Copying test script to VM..."
    if ! vagrant ssh <<'EOSSH'
cp /vagrant/tests/run-tests-in-vm.sh /tmp/run-tests-in-vm.sh
chmod +x /tmp/run-tests-in-vm.sh
EOSSH
    then
        error "Failed to copy test script"
        return 1
    fi

    # Execute the test script from /tmp with test selection arguments
    local test_cmd="/tmp/run-tests-in-vm.sh"
    if [[ ${#TEST_ARGS[@]} -gt 0 ]]; then
        test_cmd="$test_cmd ${TEST_ARGS[*]}"
        info "Running selected tests: ${TEST_ARGS[*]}"
    fi

    # Use heredoc but explicitly exit with the command's exit code
    vagrant ssh <<EOSSH
sudo $test_cmd
exit \$?
EOSSH
    local exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        success "Tests completed successfully"
        return 0
    else
        error "Tests failed (exit code: $exit_code)"
        return 1
    fi
}

# Destroy the VM
destroy_vm() {
    local force="${1:-false}"

    cd "${TRACEE_ROOT}"

    if [[ "$force" == "true" ]]; then
        info "Destroying VM..."
        vagrant destroy -f
        success "VM destroyed"
    else
        info "Halting VM..."
        vagrant halt
        info "VM halted (use 'vagrant destroy' to remove completely)"
    fi
}

# Show debugging instructions
show_debug_instructions() {
    echo ""
    echo "========================================"
    echo "   VM Debugging Instructions"
    echo "========================================"
    echo ""
    echo "The VM has been preserved for debugging."
    echo ""
    echo "To access the VM:"
    echo "  cd ${TRACEE_ROOT}"
    echo "  vagrant ssh"
    echo ""
    echo "Test logs are available at:"
    echo "  ${TRACEE_ROOT}/tests/vm-test-logs/"
    echo ""
    echo "To re-run tests manually inside the VM:"
    echo "  vagrant ssh"
    echo "  sudo /vagrant/tests/run-tests-in-vm.sh"
    echo ""
    echo "When done debugging, destroy the VM:"
    echo "  cd ${TRACEE_ROOT}"
    echo "  vagrant destroy -f"
    echo ""
    echo "========================================"
    echo ""
}

# Main execution
main() {
    echo "========================================"
    echo "  Tracee VM Test Environment"
    echo "========================================"
    echo ""

    # Parse arguments
    parse_args "$@"

    # Check prerequisites
    if ! check_prerequisites; then
        exit 1
    fi

    # Change to tracee root
    cd "${TRACEE_ROOT}"

    # Start VM
    if ! start_vm; then
        error "Failed to start VM, cannot proceed with tests"
        exit 1
    fi

    # Run tests
    local test_exit_code=0
    if ! run_tests_in_vm; then
        test_exit_code=1
    fi

    # Handle VM cleanup based on test results
    echo ""
    if [[ ${test_exit_code} -eq 0 ]]; then
        success "All tests passed!"
        echo ""

        if [[ "${KEEP_VM_ON_SUCCESS}" == "true" ]]; then
            warn "VM preserved for inspection (--keep-vm specified)"
            show_debug_instructions
        else
            info "Cleaning up VM..."
            destroy_vm true
            success "VM destroyed"
        fi

        echo ""
        success "Test run completed successfully 🎉"
        exit 0
    else
        error "Some tests failed"
        echo ""
        warn "VM preserved for debugging"
        show_debug_instructions
        exit 1
    fi
}

# Trap cleanup on script exit
cleanup_on_interrupt() {
    echo ""
    warn "Script interrupted"

    if is_vm_running; then
        warn "VM is still running"
        show_debug_instructions
    fi

    exit 130
}

trap cleanup_on_interrupt INT TERM

# Run main
main "$@"


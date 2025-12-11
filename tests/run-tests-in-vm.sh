#!/bin/bash
#
# Tracee Test Orchestration Script (runs inside VM)
#
# This script runs all Tracee tests inside the Vagrant VM with proper isolation.
# It should be executed with root privileges from within the VM.
#
# Exit codes:
#   0 - All tests passed
#   1 - One or more tests failed
#   2 - Build failed
#   3 - Prerequisites check failed

set -e  # Exit on error (we'll handle specific failures)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Test results tracking
TESTS_FAILED=0
TESTS_PASSED=0
TEST_RESULTS=()

# Test suite flags (default: run all)
RUN_UNIT=true
RUN_INTEGRATION=true
RUN_E2E_INST=true
RUN_E2E_NET=true
SELECTIVE_RUN=false  # Set to true if user specifies specific tests

# Log directory
LOG_DIR="/vagrant/tests/vm-test-logs"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="${LOG_DIR}/test-run-${TIMESTAMP}.log"

# Initialize logging
init_logging() {
    mkdir -p "${LOG_DIR}"
    info "Test run started at $(date)" | tee "${LOG_FILE}"
    info "Logs will be saved to: ${LOG_FILE}"
}

# Check prerequisites
check_prerequisites() {
    info "Checking prerequisites..."

    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (use sudo)"
        return 3
    fi

    # Check if we're in the tracee directory
    if [[ ! -f "/vagrant/Makefile" ]] && [[ ! -f "$(pwd)/Makefile" ]]; then
        error "Not in Tracee root directory"
        return 3
    fi

    # Change to tracee directory if needed
    if [[ -f "/vagrant/Makefile" ]]; then
        cd /vagrant
    fi

    # Check essential tools
    local missing_tools=()
    for tool in make go clang docker; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        error "Missing required tools: ${missing_tools[*]}"
        return 3
    fi

    success "Prerequisites check passed"
    return 0
}

# Clean previous builds
clean_builds() {
    info "Cleaning previous builds..."
    make clean 2>&1 | tee -a "${LOG_FILE}" || warn "Clean failed (may be first run)"
    success "Clean completed"
}

# Build Tracee
build_tracee() {
    info "Building Tracee (this may take several minutes)..."

    if make all 2>&1 | tee -a "${LOG_FILE}"; then
        success "Build completed successfully"
        return 0
    else
        error "Build failed"
        return 2
    fi
}

# Run unit tests
run_unit_tests() {
    info "Running unit tests..."

    local unit_log="${LOG_DIR}/unit-tests-${TIMESTAMP}.log"

    make test-unit 2>&1 | tee "${unit_log}" | tee -a "${LOG_FILE}"
    local exit_code=${PIPESTATUS[0]}

    if [[ $exit_code -eq 0 ]]; then
        success "Unit tests passed"
        TEST_RESULTS+=("✓ Unit tests: PASSED")
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        error "Unit tests failed (exit code: $exit_code)"
        TEST_RESULTS+=("✗ Unit tests: FAILED (see ${unit_log})")
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Run integration tests
run_integration_tests() {
    info "Running integration tests (requires root and eBPF support)..."

    local integration_log="${LOG_DIR}/integration-tests-${TIMESTAMP}.log"

    # Integration tests require root and eBPF
    # The Makefile tries to write coverage to ./integration-coverage.txt
    # which fails on 9p mounts with permission denied
    # We override the go test command to skip coverage for VM testing

    info "Building syscaller binary..."
    if ! make embedded-dirs ./dist/syscaller 2>&1 | tee -a "${LOG_FILE}"; then
        error "Failed to build syscaller"
        TEST_RESULTS+=("✗ Integration tests: FAILED (build error)")
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi

    info "Running go test (without coverage to avoid 9p permission issues)..."
    # Run the same test command as the Makefile but without -coverprofile
    GOOS=linux CC=clang GOARCH=amd64 GOFIPS140=off \
        CGO_CFLAGS="-I/vagrant/dist/libbpf/include" \
        CGO_LDFLAGS="-L/vagrant/dist/libbpf/obj -lbpf" \
        go test \
        -tags core,ebpf,lsmsupport \
        -ldflags="-s=false -w=false -extldflags \"-lelf -lz\" -X main.version=\"$(cat /vagrant/VERSION)\"" \
        -shuffle on \
        -timeout 20m \
        -race \
        -v \
        -p 1 \
        -count=1 \
        ./tests/integration/... 2>&1 | tee "${integration_log}" | tee -a "${LOG_FILE}"

    local exit_code=${PIPESTATUS[0]}

    if [[ $exit_code -eq 0 ]]; then
        success "Integration tests passed"
        TEST_RESULTS+=("✓ Integration tests: PASSED")
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        error "Integration tests failed (exit code: $exit_code)"
        TEST_RESULTS+=("✗ Integration tests: FAILED (see ${integration_log})")
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Run e2e instrumentation tests
run_e2e_inst_tests() {
    info "Running e2e instrumentation tests..."

    local e2e_inst_log="${LOG_DIR}/e2e-inst-tests-${TIMESTAMP}.log"

    # Check if e2e test script exists
    if [[ ! -f "tests/e2e-inst-test.sh" ]]; then
        warn "e2e instrumentation test script not found, skipping"
        TEST_RESULTS+=("⊘ E2E instrumentation tests: SKIPPED")
        return 0
    fi

    bash tests/e2e-inst-test.sh 2>&1 | tee "${e2e_inst_log}" | tee -a "${LOG_FILE}"
    local exit_code=${PIPESTATUS[0]}

    if [[ $exit_code -eq 0 ]]; then
        success "E2E instrumentation tests passed"
        TEST_RESULTS+=("✓ E2E instrumentation tests: PASSED")
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        error "E2E instrumentation tests failed (exit code: $exit_code)"
        TEST_RESULTS+=("✗ E2E instrumentation tests: FAILED (see ${e2e_inst_log})")
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Run e2e network tests
run_e2e_net_tests() {
    info "Running e2e network tests..."

    local e2e_net_log="${LOG_DIR}/e2e-net-tests-${TIMESTAMP}.log"

    # Check if e2e test script exists
    if [[ ! -f "tests/e2e-net-test.sh" ]]; then
        warn "e2e network test script not found, skipping"
        TEST_RESULTS+=("⊘ E2E network tests: SKIPPED")
        return 0
    fi

    bash tests/e2e-net-test.sh 2>&1 | tee "${e2e_net_log}" | tee -a "${LOG_FILE}"
    local exit_code=${PIPESTATUS[0]}

    if [[ $exit_code -eq 0 ]]; then
        success "E2E network tests passed"
        TEST_RESULTS+=("✓ E2E network tests: PASSED")
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        error "E2E network tests failed (exit code: $exit_code)"
        TEST_RESULTS+=("✗ E2E network tests: FAILED (see ${e2e_net_log})")
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Print test summary
print_summary() {
    echo ""
    echo "========================================"
    echo "         TEST RESULTS SUMMARY           "
    echo "========================================"
    echo ""

    for result in "${TEST_RESULTS[@]}"; do
        echo "  $result"
    done

    echo ""
    echo "----------------------------------------"
    echo "Total: ${TESTS_PASSED} passed, ${TESTS_FAILED} failed"
    echo "----------------------------------------"
    echo ""

    if [[ ${TESTS_FAILED} -eq 0 ]]; then
        success "All tests passed! 🎉"
        return 0
    else
        error "${TESTS_FAILED} test suite(s) failed"
        return 1
    fi
}

# Main execution
main() {
    echo "========================================"
    echo "   Tracee Test Suite (VM Environment)  "
    echo "========================================"
    echo ""

    init_logging

    # Check prerequisites
    if ! check_prerequisites; then
        exit 3
    fi

    # Clean previous builds
    clean_builds

    # Build Tracee
    if ! build_tracee; then
        error "Cannot proceed with tests due to build failure"
        exit 2
    fi

    # Run tests (continue even if some fail to get complete picture)
    set +e  # Don't exit on individual test failures

    if [[ "$SELECTIVE_RUN" == "true" ]]; then
        info "Running selected test suites..."
    else
        info "Running all test suites..."
    fi

    [[ "$RUN_UNIT" == "true" ]] && run_unit_tests
    [[ "$RUN_INTEGRATION" == "true" ]] && run_integration_tests
    [[ "$RUN_E2E_INST" == "true" ]] && run_e2e_inst_tests
    [[ "$RUN_E2E_NET" == "true" ]] && run_e2e_net_tests

    # Print summary and exit with appropriate code
    print_summary | tee -a "${LOG_FILE}"
    local summary_exit=${PIPESTATUS[0]}

    info "Test run completed at $(date)" | tee -a "${LOG_FILE}"

    exit $summary_exit
}

# Handle script arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Run Tracee test suite inside VM (requires root)"
        echo ""
        echo "Options:"
        echo "  --unit              Run only unit tests"
        echo "  --integration       Run only integration tests"
        echo "  --e2e-inst          Run only e2e instrumentation tests"
        echo "  --e2e-net           Run only e2e network tests"
        echo "  --help, -h          Show this help message"
        echo ""
        echo "Multiple options can be combined to run specific test suites."
        echo "If no test options are specified, all tests will run."
        echo ""
        echo "Examples:"
        echo "  sudo $0                           # Run all tests"
        echo "  sudo $0 --unit                    # Run only unit tests"
        echo "  sudo $0 --integration --e2e-inst  # Run integration and e2e inst tests"
        echo ""
        exit 0
        ;;
    *)
        # Parse test selection arguments
        if [[ $# -gt 0 ]]; then
            # User specified specific tests, so disable all by default
            RUN_UNIT=false
            RUN_INTEGRATION=false
            RUN_E2E_INST=false
            RUN_E2E_NET=false
            SELECTIVE_RUN=true

            # Enable only the requested tests
            for arg in "$@"; do
                case "$arg" in
                    --unit)
                        RUN_UNIT=true
                        ;;
                    --integration)
                        RUN_INTEGRATION=true
                        ;;
                    --e2e-inst)
                        RUN_E2E_INST=true
                        ;;
                    --e2e-net)
                        RUN_E2E_NET=true
                        ;;
                    *)
                        echo "Unknown option: $arg"
                        echo "Run '$0 --help' for usage information"
                        exit 1
                        ;;
                esac
            done
        fi
        main "$@"
        ;;
esac


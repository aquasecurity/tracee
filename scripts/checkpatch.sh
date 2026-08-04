#!/bin/bash
#
# checkpatch.sh - Local development script to run PR tests.
#
# Usage: ./scripts/checkpatch.sh [OPTIONS] [commit-ref]
# If no commit-ref is provided, checks HEAD commit.
#
# All make targets invoked here containerize themselves (see the root
# Makefile): the only host dependencies are git, make and a container
# engine (docker or podman). Tool versions are pinned in the build
# environment image.
#

set -euo pipefail

# Source lib.sh for common functions
__LIB_DIR="${0%/*}"
# shellcheck disable=SC1091
. "${__LIB_DIR}/lib.sh"

# Print functions using lib.sh
print_info() {
    info "$1"
}

print_success() {
    info "[PASS] $1"
}

print_warning() {
    warn "$1"
}

print_error() {
    error "$1"
}

print_header() {
    info ""
    info "=========================================="
    info " $1"
    info "=========================================="
}

show_help() {
    cat << EOF
Usage: $0 [OPTIONS] [commit-ref]

Tracee Checkpatch Script - Run PR tests locally to accelerate development

This script mimics the tests that run when pushing a PR to the tracee repo.
It runs the same checks as the GitHub Actions workflow to catch issues early.

Arguments:
  git-ref       Git reference to check (default: HEAD)
                Can be a commit hash, branch name, or tag

Options:
  -h, --help              Show this help message and exit

  --skip-docs             Skip documentation verification
  --skip-code-analysis    Skip code analysis (linting, formatting, etc.)
  --skip-unit-tests       Skip unit tests
  --skip-pr-format        Skip PR commit formatting
  --fast                  Skip slow checks (static analysis + unit tests), run formatting and linting only
  --distro DISTRO         Build environment distro for all checks (alpine|ubuntu, default: alpine)

Environment Variables:
  BASE_REF                Git reference to compare against (auto-detected from remotes)
  NATIVE                  NATIVE=1 runs the checks with the host toolchain instead
                          of the containerized build environment

Test Categories:
  1. Documentation Verification - Ensures .1.md and .1 man page files are synchronized
  2. Code Analysis - Runs formatting, linting, vet, staticcheck, errcheck, and govulncheck
  3. Unit Tests - Runs Go unit tests and script unit tests
  4. PR Formatting - Displays commit messages in PR-ready format

Examples:
  $0                             # Check HEAD (default)
  $0 HEAD~1                      # Check previous commit
  $0 main                        # Check main branch
  $0 abc123def                   # Check specific commit hash
  $0 --fast                      # Quick checks (formatting + linting only)
  $0 --skip-docs                 # Skip documentation verification
  BASE_REF=v1.0.0 $0             # Compare against v1.0.0 instead of auto-detected base
  $0 --help                      # Show this help

Dependencies:
  Required: make, git, and a container engine (docker or podman)
  With NATIVE=1: make, git, go and the tools from the build environment image

Exit Codes:
  0 - All tests passed
  1 - One or more tests failed or error occurred
EOF
}

# Options
SKIP_DOCS=false
SKIP_CODE_ANALYSIS=false
SKIP_UNIT_TESTS=false
SKIP_PR_FORMAT=false
FAST_MODE=false

# Parse arguments
COMMAND_MODE=""
while [[ $# -gt 0 ]]; do
    case $1 in
        -h | --help)
            show_help
            exit 0
            ;;
        pr-format)
            COMMAND_MODE="pr-format"
            ;;
        --skip-docs)
            SKIP_DOCS=true
            ;;
        --skip-code-analysis)
            SKIP_CODE_ANALYSIS=true
            ;;
        --skip-unit-tests)
            SKIP_UNIT_TESTS=true
            ;;
        --skip-pr-format)
            SKIP_PR_FORMAT=true
            ;;
        --distro)
            shift
            if [[ $# -eq 0 ]]; then
                print_error "--distro requires an argument (alpine|ubuntu)"
                exit 1
            fi
            export DISTRO="$1"
            ;;
        --ignore-missing-tools)
            print_error "--ignore-missing-tools was removed: checks run in a container"
            print_error "with all tools preinstalled. Use NATIVE=1 for a host-toolchain run."
            exit 1
            ;;
        --fast)
            FAST_MODE=true
            SKIP_UNIT_TESTS=true
            ;;
        -*)
            print_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
        *)
            GIT_REF="$1"
            break
            ;;
    esac
    shift
done

# Detect the remote/main ref to compare against. Tries private/main,
# upstream/main, origin/main, then the first remote that has a main branch.
detect_base_ref() {
    for r in private upstream origin $(git remote 2>/dev/null); do
        if git rev-parse --verify "${r}/main" >/dev/null 2>&1; then
            echo "${r}/main"
            return
        fi
    done
    echo "origin/main"
}

# Get the git reference to check (default to HEAD)
GIT_REF=${GIT_REF:-HEAD}
# Get the base reference (from environment variable or auto-detect)
BASE_REF="${BASE_REF:-$(detect_base_ref)}"

print_info "Tracee Checkpatch Script"
print_info "Checking: ${GIT_REF}"
print_info "Comparing against: ${BASE_REF}"

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    print_error "Not in a git repository!"
    exit 1
fi

# Check if git reference exists
if ! git rev-parse --verify "${GIT_REF}" > /dev/null 2>&1; then
    print_error "Git reference '${GIT_REF}' does not exist!"
    exit 1
fi

# Track overall success
OVERALL_SUCCESS=true

run_test_section() {
    local section_name=$1
    local test_function=$2

    print_header "${section_name}"

    if "${test_function}"; then
        print_success "${section_name} completed successfully"
        return 0
    else
        print_error "${section_name} failed"
        OVERALL_SUCCESS=false
        return 1
    fi
}

# shellcheck disable=SC2329 # invoked indirectly via run_test_section
verify_docs() {
    print_info "Verifying documentation synchronization..."

    if [[ ! -f "scripts/verify_man_md_sync.sh" ]]; then
        print_warning "scripts/verify_man_md_sync.sh not found, skipping documentation verification"
        return 0
    fi

    if ! bash scripts/verify_man_md_sync.sh --base-ref "${BASE_REF}" --target-ref "${GIT_REF}"; then
        print_error "Documentation verification failed"
        print_error "- .1.md changes require corresponding .1 changes"
        print_info "Run 'make man' to regenerate man pages"
        return 1
    fi

    return 0
}

# Runs a single make target, capturing output so passing checks stay quiet.
# Arguments:
#   $1 - human-readable label (e.g. "Go vet")
#   $2 - make target (e.g. "check-vet")
# Returns 0 on success, 1 on failure.
# shellcheck disable=SC2329 # invoked indirectly via verify_analyze_code
run_check_target() {
    local label="$1"
    local target="$2"

    local output
    local rc=0
    output=$(make "${target}" 2>&1) || rc=$?

    if ((rc == 0)); then
        print_success "  [ok] ${label} passed"
        return 0
    fi

    echo "${output}"
    print_error "  [fail] ${label} failed"
    return 1
}

# shellcheck disable=SC2329 # invoked indirectly via run_test_section
verify_analyze_code() {
    print_info "Verifying and analyzing code..."
    print_info "Note: the build environment image is built automatically if needed (first time only)"

    print_info "Running formatting checks..."
    run_check_target "Code formatting" "check-fmt" || return 1

    print_info "Running linting checks..."
    run_check_target "Linting" "check-lint" || return 1

    if ${FAST_MODE}; then
        print_info "Fast mode: skipping static analysis checks"
        return 0
    fi

    print_info "Running comprehensive code checks..."

    print_info "  -> Running Go vet analysis..."
    run_check_target "Go vet" "check-vet" || return 1

    print_info "  -> Running StaticCheck analysis..."
    run_check_target "StaticCheck" "check-staticcheck" || return 1

    print_info "  -> Running errcheck analysis..."
    run_check_target "errcheck" "check-err" || return 1

    print_info "  -> Running govulncheck analysis..."
    run_check_target "govulncheck" "check-vulncheck" || return 1

    print_success "All code analysis checks passed"

    return 0
}

# shellcheck disable=SC2329 # invoked indirectly via run_test_section
unit_tests() {
    print_info "Running unit tests..."

    print_info "Running Go unit tests..."
    if make test-unit; then
        print_success "Go unit tests passed"
    else
        print_error "Go unit tests failed"
        return 1
    fi

    print_info "Running script infrastructure tests..."
    if make run-scripts-test-unit > /dev/null 2>&1; then
        print_success "Script infrastructure tests passed"
    else
        print_error "Script infrastructure tests failed"
        return 1
    fi

    return 0
}

pr_format() {
    print_info "Generating PR commit format..."

    if ! command -v git > /dev/null 2>&1; then
        print_error "git is required for PR formatting"
        return 1
    fi

    print_info "PR Comment Format:"
    echo ""
    echo "--- PR Comment BEGIN ---"
    echo ""

    git log "${BASE_REF}..HEAD" --pretty=format:'%h **%s**' 2> /dev/null || {
        print_warning "Could not generate commit log from ${BASE_REF} to HEAD"
        print_info "This might be because you're not on a branch that diverges from ${BASE_REF}"
        return 0
    }

    echo ""
    echo ""

    local output
    local commit
    local body
    output=$(git rev-list "${BASE_REF}..HEAD" 2> /dev/null | while IFS= read -r commit; do
        body="$(git show --no-patch --format=%b "${commit}" | sed ':a;N;$!ba;s/\n$//')"
        if [[ -n "${body}" ]]; then
            git show -s "${commit}" --color=always --format='%C(auto,yellow)%h%Creset **%C(auto,red)%s%Creset**%n'
            echo "> ${body//$'\n'/$'\n'> }"
            echo
            echo "--"
            echo
        fi
    done)

    echo "${output}"
    echo ""
    echo "--- PR Comment END ---"
    echo ""

    return 0
}

check_dependencies() {
    print_info "Checking dependencies..."

    local basic_tools=("make" "git")
    local tool
    for tool in "${basic_tools[@]}"; do
        if ! command -v "${tool}" > /dev/null 2>&1; then
            print_error "${tool} is required but not installed"
            return 1
        fi
    done

    if [[ "${NATIVE:-0}" = "1" ]]; then
        print_info "NATIVE=1: using the host toolchain"
        if ! command -v go > /dev/null 2>&1; then
            print_error "go is required for NATIVE=1 but not installed"
            return 1
        fi
        print_info "Go version: $(go version | grep -o 'go[0-9]\+\.[0-9]\+')"
        return 0
    fi

    # containerized (default): a container engine is the only toolchain dependency
    local engine
    for engine in docker podman; do
        if command -v "${engine}" > /dev/null 2>&1; then
            print_info "Container engine: $(${engine} --version 2>/dev/null | head -n1)"
            print_info "Note: all code quality tools run in the build environment image with pinned versions"
            return 0
        fi
    done

    print_error "No container engine found (docker or podman)"
    print_info "Install one, or run with NATIVE=1 if the host has a full build toolchain"
    return 1
}

main() {
    print_header "Dependency Check"
    if ! check_dependencies; then
        print_error "Dependency check failed"
        exit 1
    fi
    print_success "Dependencies check completed"

    if ! ${SKIP_DOCS}; then
        run_test_section "Documentation Verification" verify_docs
    else
        print_info "Skipping documentation verification"
    fi

    if ! ${SKIP_CODE_ANALYSIS}; then
        run_test_section "Code Analysis" verify_analyze_code
    else
        print_info "Skipping code analysis"
    fi

    if ! ${SKIP_UNIT_TESTS}; then
        run_test_section "Unit Tests" unit_tests
    else
        print_info "Skipping unit tests"
    fi

    if ! ${SKIP_PR_FORMAT}; then
        run_test_section "PR Formatting" pr_format
    else
        print_info "Skipping PR formatting"
    fi

    print_header "Summary"
    if ${OVERALL_SUCCESS}; then
        print_success "All checks passed!"
        print_info "Your commit is ready for PR submission."
        exit 0
    else
        print_error "Some checks failed."
        print_info "Please fix the issues above before submitting a PR."
        exit 1
    fi
}

# If pr-format command mode, just run that and exit
if [[ "${COMMAND_MODE}" = "pr-format" ]]; then
    BASE_REF="${BASE_REF:-$(detect_base_ref)}"
    pr_format
    exit $?
fi

main "$@"

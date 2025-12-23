#!/bin/bash

# checkpatch.sh - Local development script to run PR tests
# Usage: ./scripts/checkpatch.sh [commit-ref]
# If no commit-ref is provided, checks HEAD commit

set -e

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

# Function to show help
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
  --ignore-missing-tools  Continue even if optional tools are missing
  --fast                  Skip slow checks (static analysis + unit tests), run formatting and linting only

Environment Variables:
  BASE_REF                Git reference to compare against (default: origin/main)

Test Categories:
  1. Documentation Verification - Ensures .1.md and .1 man page files are synchronized
  2. Code Analysis - Runs formatting, linting, vet, staticcheck, and errcheck
  3. Unit Tests - Runs Go unit tests and script unit tests
  4. PR Formatting - Displays commit messages in PR-ready format

Examples:
  $0                             # Check HEAD (default)
  $0 HEAD~1                      # Check previous commit
  $0 main                        # Check main branch
  $0 abc123def                   # Check specific commit hash
  $0 --fast                      # Quick checks (formatting + linting only)
  $0 --skip-docs                 # Skip documentation verification
  $0 --skip-code-analysis        # Skip code analysis if tools missing
  $0 --ignore-missing-tools      # Continue despite missing tools
  BASE_REF=v1.0.0 $0             # Compare against v1.0.0 instead of origin/main
  $0 --help                      # Show this help

Dependencies:
  Required: go, make, git
  Optional: revive, staticcheck, errcheck (will be skipped if not installed)

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
IGNORE_MISSING_TOOLS=false
FAST_MODE=false

# Parse arguments
COMMAND_MODE=""
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
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
        --ignore-missing-tools)
            IGNORE_MISSING_TOOLS=true
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

# Get the git reference to check (default to HEAD)
GIT_REF=${GIT_REF:-HEAD}
# Get the base reference (from environment variable or default)
BASE_REF="${BASE_REF:-origin/main}"

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

# Function to run a test section
run_test_section() {
    local section_name=$1
    local test_function=$2

    print_header "$section_name"

    if $test_function; then
        print_success "$section_name completed successfully"
        return 0
    else
        print_error "$section_name failed"
        OVERALL_SUCCESS=false
        return 1
    fi
}

# Test 1: Verify Documentation Synchronization
verify_docs() {
    print_info "Verifying documentation synchronization..."

    # Check if verify_man_md_sync.sh exists
    if [[ ! -f "scripts/verify_man_md_sync.sh" ]]; then
        print_warning "scripts/verify_man_md_sync.sh not found, skipping documentation verification"
        return 0
    fi

    # Run the documentation verification script
    if ! bash scripts/verify_man_md_sync.sh --base-ref "${BASE_REF}" --target-ref "${GIT_REF}"; then
        print_error "Documentation verification failed"
        print_error "- .1.md changes require corresponding .1 changes"
        print_info "Run 'make -f builder/Makefile.man man-run' to regenerate man pages"
        return 1
    fi

    return 0
}

# Test 2: Verify and Analyze Code (equivalent to make check-pr code analysis)
verify_analyze_code() {
    print_info "Verifying and analyzing code..."

    # Run comprehensive code analysis equivalent to make check-pr
    print_info "Running formatting checks..."
    if output=$(make -f builder/Makefile.checkers fmt-check 2>&1); then
        print_success "Code formatting passed"
    else
        print_error "Code formatting failed"
        if echo "$output" | grep -q "missing required tool"; then
            local missing_tool=$(echo "$output" | grep "missing required tool" | sed 's/.*missing required tool //')
            print_warning "Missing required tool: $missing_tool"

            case "$missing_tool" in
                "clang-format-12")
                    print_info "clang-format-12 is required for eBPF C code formatting."
                    print_info "Install using your system's official package manager:"
                    print_info " Ubuntu/Debian: sudo apt-get update && sudo apt-get install clang-format-12"
                    print_info " Fedora/CentOS: sudo dnf install clang-tools-extra"
                    print_info "See https://clang.llvm.org/docs/ClangFormat.html for more details."
                    ;;
                "goimports-reviser")
                    print_info "Install with: go install github.com/incu6us/goimports-reviser/v3@v3.8.2"
                    ;;
            esac

            if $IGNORE_MISSING_TOOLS; then
                print_warning "Ignoring missing tool error and continuing..."
            else
                return 1
            fi
        else
            echo "$output"
            return 1
        fi
    fi

    print_info "Running linting checks..."
    if output=$(make -f builder/Makefile.checkers lint-check 2>&1); then
        print_success "Linting passed"
    else
        print_error "Linting failed"
        if echo "$output" | grep -q "missing required tool"; then
            local missing_tool=$(echo "$output" | grep "missing required tool" | sed 's/.*missing required tool //')
            print_warning "Missing required tool: $missing_tool"
            print_info "Install with: go install github.com/mgechev/revive@v1.7.0"

            if $IGNORE_MISSING_TOOLS; then
                print_warning "Ignoring missing tool error and continuing..."
            else
                return 1
            fi
        else
            echo "$output"
            return 1
        fi
    fi

    # Fast mode: skip static analysis that requires compilation
    if $FAST_MODE; then
        print_info "Fast mode: skipping static analysis checks"
        return 0
    fi

    print_info "Running comprehensive code checks..."

    # Run individual checks with progress reporting
    print_info "  → Building tracee binary (this may take a moment)..."
    print_info "  → Running Go vet analysis..."
    if output=$(make check-vet 2>&1); then
        print_success "  ✓ Go vet passed"
    else
        print_error "  ✗ Go vet failed"
        if echo "$output" | grep -q "missing required tool"; then
            local missing_tool=$(echo "$output" | grep "missing required tool" | sed 's/.*missing required tool //')
            print_warning "Missing required tool: $missing_tool"
            if $IGNORE_MISSING_TOOLS; then
                print_warning "Ignoring missing tool error and continuing..."
            else
                echo "$output"
                return 1
            fi
        else
            echo "$output"
            return 1
        fi
    fi

    print_info "  → Running StaticCheck analysis..."
    if output=$(make check-staticcheck 2>&1); then
        print_success "  ✓ StaticCheck passed"
    else
        print_error "  ✗ StaticCheck failed"
        if echo "$output" | grep -q "missing required tool"; then
            local missing_tool=$(echo "$output" | grep "missing required tool" | sed 's/.*missing required tool //')
            print_warning "Missing required tool: $missing_tool"
            print_info "Install with: go install honnef.co/go/tools/cmd/staticcheck@2025.1"
            if $IGNORE_MISSING_TOOLS; then
                print_warning "Ignoring missing tool error and continuing..."
            else
                echo "$output"
                return 1
            fi
        else
            echo "$output"
            return 1
        fi
    fi

    print_info "  → Running errcheck analysis..."
    if output=$(make check-err 2>&1); then
        print_success "  ✓ errcheck passed"
    else
        print_error "  ✗ errcheck failed"
        if echo "$output" | grep -q "missing required tool"; then
            local missing_tool=$(echo "$output" | grep "missing required tool" | sed 's/.*missing required tool //')
            print_warning "Missing required tool: $missing_tool"
            print_info "Install with: go install github.com/kisielk/errcheck@v1.9.0"
            if $IGNORE_MISSING_TOOLS; then
                print_warning "Ignoring missing tool error and continuing..."
            else
                echo "$output"
                return 1
            fi
        else
            echo "$output"
            return 1
        fi
    fi

    print_success "All code analysis checks passed"

    return 0
}

# Test 3: Unit Tests
unit_tests() {
    print_info "Running unit tests..."

    # Run unit tests
    print_info "Running Go unit tests..."
    if make test-unit; then
        print_success "Go unit tests passed"
    else
        print_error "Go unit tests failed"
        return 1
    fi

    # Run script unit tests (tests lib.sh infrastructure functions)
    print_info "Running script infrastructure tests..."
    if make run-scripts-test-unit > /dev/null 2>&1; then
        print_success "Script infrastructure tests passed"
    else
        print_error "Script infrastructure tests failed"
        return 1
    fi

    return 0
}

# Test 3: PR Formatting (equivalent to make format-pr)
pr_format() {
    print_info "Generating PR commit format..."

    if ! command -v git &> /dev/null; then
        print_error "git is required for PR formatting"
        return 1
    fi

    print_info "PR Comment Format:"
    echo ""
    echo "👇 PR Comment BEGIN"
    echo ""

    # Display commits in PR format (without colors for PR comment)
    git log $BASE_REF..HEAD --pretty=format:'%h **%s**' 2>/dev/null || {
        print_warning "Could not generate commit log from $BASE_REF to HEAD"
        print_info "This might be because you're not on a branch that diverges from $BASE_REF"
        return 0
    }

    echo ""
    echo ""

    # Display commit bodies if they exist (with color for terminal, quote prefix for PR)
    output=$(git rev-list $BASE_REF..HEAD 2>/dev/null | while read commit; do
        body="$(git show --no-patch --format=%b $commit | sed ':a;N;$!ba;s/\n$//')"
        if [ -n "$body" ]; then
            git show -s $commit --color=always --format='%C(auto,yellow)%h%Creset **%C(auto,red)%s%Creset**%n'
            echo "$body" | sed 's/^/> /'
            echo
            echo "--"
            echo
        fi
    done)

    echo "$output"
    echo ""
    echo "👆 PR Comment END"
    echo ""

    return 0
}

# Check for required dependencies
check_dependencies() {
    print_info "Checking dependencies..."

    # Check for basic tools
    local basic_tools=("go" "make" "git")
    for tool in "${basic_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            print_error "$tool is required but not installed"
            return 1
        fi
    done

    # Ensure Go bin directory is in PATH for Go tools
    local go_bin_path="$(go env GOPATH)/bin"
    if [[ ":$PATH:" != *":$go_bin_path:"* ]]; then
        print_info "Adding Go bin directory to PATH: $go_bin_path"
        export PATH="$PATH:$go_bin_path"
    fi

    # Check Go version
    local go_version=$(go version | grep -o 'go[0-9]\+\.[0-9]\+')
    print_info "Go version: $go_version"

    # Check for optional tools and warn if missing
    local optional_tools=(
        "revive:github.com/mgechev/revive@v1.7.0:go install"
        "staticcheck:honnef.co/go/tools/cmd/staticcheck@2025.1:go install"
        "errcheck:github.com/kisielk/errcheck@v1.9.0:go install"
        "clang-format-12:Install via official package manager (e.g., 'sudo apt-get install clang-format-12'):Refer to your OS package manager"
        "goimports-reviser:github.com/incu6us/goimports-reviser/v3@v3.8.2:go install"
    )

    for tool_info in "${optional_tools[@]}"; do
        local tool_name="${tool_info%%:*}"
        local tool_package="${tool_info#*:}"
        local install_method="${tool_info##*:}"
        tool_package="${tool_package%:*}"

        if ! command -v "$tool_name" &> /dev/null; then
            print_warning "$tool_name not found."
            if [[ "$install_method" == "go install" ]]; then
                print_info "  Install with: $install_method $tool_package"
            else
                print_info "  $install_method $tool_package"
            fi
        fi
    done

    return 0
}

# Main execution
main() {
    print_header "Dependency Check"
    if ! check_dependencies; then
        print_error "Dependency check failed"
        exit 1
    fi
    print_success "Dependencies check completed"

    # Run the main test categories
    if ! $SKIP_DOCS; then
        run_test_section "Documentation Verification" verify_docs
    else
        print_info "Skipping documentation verification"
    fi

    if ! $SKIP_CODE_ANALYSIS; then
        run_test_section "Code Analysis" verify_analyze_code
    else
        print_info "Skipping code analysis"
    fi

    if ! $SKIP_UNIT_TESTS; then
        run_test_section "Unit Tests" unit_tests
    else
        print_info "Skipping unit tests"
    fi

    if ! $SKIP_PR_FORMAT; then
        run_test_section "PR Formatting" pr_format
    else
        print_info "Skipping PR formatting"
    fi

    # Final summary
    print_header "Summary"
    if $OVERALL_SUCCESS; then
        print_success "All checks passed!"
        print_info "Your commit is ready for PR submission."
        exit 0
    else
        print_error "Some checks failed! ❌"
        print_info "Please fix the issues above before submitting a PR."
        exit 1
    fi
}

# If pr-format command mode, just run that and exit
if [ "$COMMAND_MODE" = "pr-format" ]; then
    BASE_REF="${BASE_REF:-origin/main}"
    pr_format
    exit $?
fi

# Run main function
main "$@"
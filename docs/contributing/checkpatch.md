# Code Quality Guide

This guide covers all code quality tools and checks for Tracee development. The checkpatch script (`scripts/checkpatch.sh`) powers the `make check-pr` command and provides comprehensive PR verification for all developers.

## Purpose

This script now **powers the official `make check-pr` command** and includes all necessary checks for PR submission:

- **Documentation verification**: Man page synchronization checks
- **Code analysis**: Comprehensive formatting, linting, and static analysis
- **Unit tests**: Go and script unit tests
- **PR formatting**: Commit message formatting for PR descriptions
- **Enhanced UX**: Better error messages, tool installation guidance, and flexible options

## Usage

### Quick Start

```bash
# Official way - use make targets (recommended)
make check-pr                   # Full comprehensive checks
make check-pr-fast              # Quick checks (skip static analysis + unit tests)
make check-pr-skip-docs         # Skip documentation verification
make check-pr-skip-tests        # Skip unit tests

# Direct script usage for advanced options
./scripts/checkpatch.sh                   # Check HEAD
./scripts/checkpatch.sh abc123def         # Check specific commit
./scripts/checkpatch.sh HEAD~1            # Check previous commit
./scripts/checkpatch.sh --skip-unit-tests # Skip time-consuming tests
./scripts/checkpatch.sh --help            # Show all options
```

### All Available Commands

**Primary Make Targets (Recommended):**
```bash
make check-pr                   # Full comprehensive checks (recommended for PR submission)
make check-pr-fast              # Quick checks (skip static analysis + unit tests)
make check-pr-skip-docs         # Skip documentation verification
make check-pr-skip-tests        # Skip unit tests
make format-pr                  # Show what formatting changes are needed
make fix-fmt                   # Automatically fix code formatting issues
```

**Individual Check Commands:**
```bash
make -f builder/Makefile.checkers fmt-check     # Check code formatting only
make -f builder/Makefile.checkers fmt-fix       # Fix code formatting automatically
make -f builder/Makefile.checkers code-check    # Static code analysis only
```

**Direct Script Usage (Advanced):**
```bash
./scripts/checkpatch.sh [OPTIONS] [commit-ref]  # Direct script access
make check-pr ARGS="--fast --skip-docs HEAD~1"  # Pass arguments through make
```

## Test Categories

### 1. Documentation Verification

- Ensures `.1.md` and `.1` man page files are synchronized
- Runs `scripts/verify_man_md_sync.sh`
- Compares changes against `origin/main`

### 2. Code Analysis

- **Go Formatting**: Checks `gofmt` compliance
- **Linting**: Runs `revive` linter via `make check-lint`
- **Code Style**: Validates formatting via `make check-fmt`
- **Go Vet**: Static analysis via `make check-vet`
- **StaticCheck**: Advanced static analysis via `make check-staticcheck`
- **Error Check**: Unhandled error detection via `make check-err`

### 3. Unit Tests

- **Go Unit Tests**: Runs `make test-unit`
- **Script Unit Tests**: Runs `make run-scripts-test-unit`

### 4. PR Formatting

- **Commit Display**: Shows commits in PR-ready format
- **Description Generation**: Extracts commit bodies for PR descriptions

## Dependencies

### Required

- `go` (Go compiler and tools)
- `make` (Build system)
- `git` (Version control)

### Optional Tools
The script will warn if these tools are missing but continue with available checks:

- **revive**: `go install github.com/mgechev/revive@v1.7.0`
- **staticcheck**: `go install honnef.co/go/tools/cmd/staticcheck@2025.1`
- **errcheck**: `go install github.com/kisielk/errcheck@v1.9.0`

## Installation of Optional Tools

To install all optional tools at once:

```bash
# Install linting and static analysis tools
go install github.com/mgechev/revive@v1.7.0
go install honnef.co/go/tools/cmd/staticcheck@2025.1
go install github.com/kisielk/errcheck@v1.9.0

# Ensure tools are in PATH
export PATH=$PATH:$(go env GOPATH)/bin
```

## Exit Codes

- `0`: All tests passed successfully
- `1`: One or more tests failed or an error occurred

## Integration with Development Workflow

### Pre-commit Hook
You can integrate this script into your git pre-commit hooks:

```bash
#!/bin/sh
# .git/hooks/pre-commit
make check-pr-fast || exit 1
```

### IDE Integration
Many IDEs can be configured to run external scripts. Configure your IDE to run `make check-pr-fast` or `./scripts/checkpatch.sh` as a build or test step.

### Recommended Development Workflow

1. **Make your changes**
2. **Quick validation**: Run `make check-pr-fast` for immediate feedback
3. **Fix any issues**: Use `make fix-fmt` for formatting or address other issues manually
4. **Full validation**: Run `make check-pr` before PR submission
5. **Commit and push** with confidence

**Integration Options:**

- **Pre-commit hook**: Add `make check-pr-fast || exit 1` to `.git/hooks/pre-commit`
- **IDE integration**: Configure your IDE to run `make check-pr-fast` as a build step

## Troubleshooting

### Common Issues

**Missing Tools Warning**
```
⚠ revive not found. Install with: go install github.com/mgechev/revive@v1.7.0
```
*Solution*: Install the missing tool or ignore if you don't need that specific check.

**Documentation Mismatch**
```
✗ Documentation verification failed
- tracee.1.md change requires corresponding tracee.1 change
```
*Solution*: Run `make -f builder/Makefile.man` to regenerate man pages.

**Formatting Issues**
```
✗ Go formatting issues found:
```
*Solution*: Run `make fix-fmt` or `make -f builder/Makefile.checkers fmt-fix` to fix formatting automatically.

**Protocol Buffer Issues**
```
✗ Protobuf files need regeneration
```
*Solution*: Run `make -f builder/Makefile.protoc` to regenerate Go code from `.proto` files.

### Performance Tips

- The script fetches `origin/main` with `--depth=1` for efficiency
- Dependencies are checked once at the beginning
- Tests run in the order of fastest to slowest (docs → code analysis → unit tests)

## Extending the Script

To add additional test categories:

1. Create a new test function following the pattern of existing functions
2. Add it to the main execution in the `main()` function
3. Update the help text and documentation

## Comparison with CI

This script covers the basic PR tests but does not include:

- Integration tests (require elevated privileges)
- Performance tests (resource intensive)
- Multi-kernel testing (requires special infrastructure)
- Build verification for other tools

For the complete test suite, the CI pipeline in GitHub Actions is still required.

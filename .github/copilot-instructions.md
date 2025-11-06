# Copilot Instructions for Tracee

## Repository Overview

Tracee is a runtime security and observability tool that uses eBPF technology to tap into system activity and expose events ranging from factual system information to sophisticated security detections. It's a large, mature codebase (~500K+ lines) written primarily in Go and C (eBPF), targeting Linux systems with kernel 4.18+.

### Key Technologies
- **Languages**: Go (1.24+), C (eBPF), Shell scripts
- **Build Tools**: Make, Clang 12+, Go toolchain
- **Frameworks**: eBPF/libbpf, gRPC, Kubernetes operators
- **Target Platforms**: Linux x86_64, aarch64

## Build Instructions & Environment Setup

### Essential Prerequisites
Always ensure these requirements before building:
- **Go 1.24+** (specifically required - earlier versions will fail)
- **Clang 12+** (minimum version enforced by Makefile)
- **pkg-config, build-essential, libelf-dev, libzstd-dev** (system packages)

### Core Build Commands

```bash
# ALWAYS start with environment check
make env                    # Shows all environment variables and tool versions

# Basic building (takes 1-2 minutes)
make clean                  # Clean all build artifacts first
make all                    # Builds tracee, tracee-rules, signatures, evt, traceectl

# Individual components
make bpf                    # eBPF object only
make tracee                 # Main unified binary
make signatures             # Go plugin signatures
make tracee-bench           # Benchmarking tool
```

### Testing Commands

```bash
# Unit tests (takes ~6-8 seconds)
make test-unit              # Fast, comprehensive unit tests

# Integration tests (requires root privileges)
sudo make test-integration  # Some tests skip without root

# Types module testing
make test-types             # Separate Go module testing

# Common module testing
make test-common            # Common module testing
```

### Validation & Linting

**IMPORTANT**: Some validation commands require additional tools not installed by default:

```bash
# Code formatting (NEEDS goimports-reviser, clang-format-19)
make check-fmt              # Will fail without proper tools
make fix-fmt                # Auto-fix formatting issues

# Other validation
make check-vet              # Go vet checks
make check-staticcheck      # Static analysis (needs staticcheck tool)
make check-err              # Error checking (needs errcheck tool)
make check-pr               # Full PR validation suite
```

**Tool Installation**: If you get "missing required tool" errors, install via:
- `goimports-reviser`: `go install github.com/incu6us/goimports-reviser/v3@v3.8.2`
- `staticcheck`: `go install honnef.co/go/tools/cmd/staticcheck@2025.1`
- `errcheck`: `go install github.com/kisielk/errcheck@v1.9.0`
- `clang-format-19`: Use system package manager or download binary

### Build Flags & Options

```bash
STATIC=1 make tracee        # Static binary linking
DEBUG=1 make tracee         # Debug symbols included
METRICS=1 make tracee       # Enable BPF metrics
BTFHUB=1 STATIC=1 make      # Embed BTF for kernel compatibility
```

### Common Build Issues & Solutions

1. **"missing required tool"**: Install the specific tool mentioned in error
2. **Go version errors**: Must use Go 1.24+, earlier versions fail validation
3. **Clang version errors**: Must use Clang 12+, checked by Makefile
4. **Integration test failures**: Many tests require root privileges
5. **libbpf build failures**: Check system has libelf-dev and build tools
6. **Permission errors in tests**: Integration tests need `sudo` for eBPF operations

## Project Architecture & Structure

### Core Directories

- **`cmd/`** - Command-line binaries
  - `tracee/` - Main unified Tracee binary
  - `tracee-rules/` - Legacy rules engine binary (deprecated)
  - `evt/` - Event generation and testing tool
  - `traceectl/` - Control plane client tool (separate Go module)

- **`pkg/`** - Main Go packages and libraries
  - `ebpf/` - eBPF program management, event processing
  - `events/` - Event definitions, parsing, filtering
  - `signatures/` - Signature engine and framework
  - `policy/` - Policy management and enforcement
  - `containers/` - Container runtime integration
  - `proctree/` - Process tree tracking
  - `filters/` - Event filtering logic

- **`pkg/ebpf/c/`** - eBPF C source code
  - `tracee.bpf.c` - Main eBPF program
  - `common/` - Shared headers and utilities
  - `maps.h`, `types.h` - eBPF data structures

- **`signatures/golang/`** - Detection signatures (Go plugins)
  - Individual `.go` files implementing specific threat detections
  - `export.go` - Signature plugin exports

### Build Artifacts

All build outputs go to `./dist/` directory:
- `tracee` - Main unified binary
- `tracee.bpf.o` - Compiled eBPF object
- `signatures/builtin.so` - Go plugin signatures
- `libbpf/` - Static libbpf build

### Configuration Files

- **`.revive.toml`** - Go linting configuration (comprehensive rules)
- **`staticcheck.conf`** - Static analysis configuration
- **`go.mod`** - Go dependencies (main module)
- **`types/go.mod`** - Separate types module
- **`Makefile`** - Primary build configuration (1100+ lines)
- **`builder/Makefile.checkers`** - Code quality validation

## Continuous Integration & Validation

### PR Workflow (`.github/workflows/pr.yaml`)
The PR workflow runs these checks:
1. **Documentation verification** - Man page sync validation
2. **Code verification** - Formatting, linting, vet, staticcheck, errcheck
3. **Build verification** - Multiple tools and components
4. **Testing** - Unit tests, integration tests, performance tests
5. **Multi-kernel testing** - Matrix of kernel versions and architectures

### Key Validation Steps
- **Formatting**: gofmt, clang-format-19, goimports-reviser
- **Linting**: revive with comprehensive rules
- **Static Analysis**: staticcheck with custom configuration
- **Error Checking**: errcheck for unchecked errors
- **Architecture Testing**: x86_64 and aarch64 builds
- **Kernel Compatibility**: Testing across kernel versions 4.18-6.12

### Test Requirements
- **Unit tests**: Run in any environment, ~6-8 seconds
- **Integration tests**: Require root privileges for eBPF operations
- **E2E tests**: Run in CI with specific kernel versions and privileges

## Development Guidelines

### Making Changes
1. **Always run formatting first**: `make fix-fmt` before commits
2. **Validate locally**: Use `make check-pr` to run full validation suite
3. **Test comprehensively**: Run both unit and integration tests when possible
4. **Check dependencies**: Use `make env` to verify tool versions

### Common Development Patterns
- **eBPF changes**: Modify files in `pkg/ebpf/c/`, rebuild with `make bpf`
- **Signature development**: Add new detection rules in `signatures/golang/`
- **Event processing**: Core logic typically in `pkg/ebpf/` and `pkg/events/`
- **Testing**: Unit tests alongside source files, E2E tests in `tests/`

### File Locations for Common Tasks
- **Add new event type**: `pkg/events/core.go`, `pkg/events/definition.go`
- **Modify eBPF program**: `pkg/ebpf/c/tracee.bpf.c`
- **Add signature**: New file in `signatures/golang/`
- **Container integration**: `pkg/containers/`
- **Policy management**: `pkg/policy/`

## Additional Notes

- **Git submodules**: Repository uses libbpf as submodule (`3rdparty/libbpf/`)
- **Multi-module**: Main module + separate `types/` module with own `go.mod`
- **Plugin architecture**: Signatures built as Go plugins loaded at runtime
- **Cross-compilation**: Supports x86_64 and aarch64 architectures
- **BTF support**: Can embed BTF for kernel compatibility via BTFHUB=1

Trust these instructions and refer to `make help` for quick command reference. When in doubt about environment setup, always run `make env` first to check tool versions and paths.

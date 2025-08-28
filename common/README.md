# Common Module

The `common` module provides shared utilities and types that can be used by both Tracee itself and Go signatures. This module is designed to be lightweight, self-contained, and independent of Tracee's core business logic.

## Purpose

This module serves as a foundation layer that provides:
- Common data structures and types
- Utility functions for basic operations
- Shared constants and definitions
- Helper functions that don't contain Tracee-specific logic

## Design Principles

### Self-Contained
The common module should be self-contained and not depend on other Tracee modules or packages. External dependencies are limited to well-established, minimal libraries that provide essential functionality.

### No Business Logic
This module **must not** contain any business logic specific to Tracee's core functionality. It should only provide generic utilities and types that could potentially be useful in other contexts.

### Minimal Dependencies
- Primarily uses Go standard library packages
- External dependencies are limited to well-established, minimal libraries (e.g., optimized hashing, LRU caches, structured logging, system interfaces)
- No dependencies on other Tracee modules or packages

## Usage

### In Consumer code
```go
import "github.com/aquasecurity/tracee/common"
```

## Packages

### Data Structures & Utilities
- **`bucketcache`** - Bucket-based caching system for efficient memory-aware data storage
- **`changelog`** - Time-ordered generic changelog data structure for tracking changes over time
- **`counter`** - Thread-safe atomic counter with overflow/underflow protection
- **`set`** - Generic set data structures for efficient collection operations

### System Integration
- **`capabilities`** - Linux capabilities handling and management for process permissions
- **`cgroup`** - Control group utilities for container and process resource management
- **`environment`** - System environment detection (kernel version, OS info, CPU/memory details)
- **`mount`** - Mount point utilities for filesystem and container mount management
- **`proc`** - `/proc` filesystem utilities for process and system information extraction
- **`system`** - System monitoring utilities for resource and performance tracking

### File & Binary Analysis
- **`elf`** - ELF file analysis and symbol extraction utilities
- **`filehash`** - File hashing with caching for efficient content verification
- **`sharedobjs`** - Shared object and library handling for dynamic loading and symbol resolution

### I/O & Utilities
- **`errfmt`** - Error formatting utilities for consistent error handling and display
- **`logger`** - Structured logging interface with filtering and formatting capabilities
- **`parsers`** - System call argument parsers for Linux syscalls (flags, capabilities, socket types, etc.)
- **`read`** - Protected file reading utilities with safety checks and error handling
- **`timeutil`** - Time-related utilities for timestamp handling and time operations

## What Belongs Here

✅ **Appropriate content:**
- Generic data structures (maps, slices utilities)
- String manipulation helpers
- Type conversion utilities  
- Mathematical helpers
- Generic algorithms
- Common constants that aren't Tracee-specific
- Basic validation functions

❌ **Inappropriate content:**
- eBPF-related logic
- Event processing functions
- Policy enforcement code
- Container runtime integrations
- Signature detection logic
- Tracee-specific configuration

## Contributing

When adding to this module, ensure that:

1. **Generic functionality** - Code should be useful beyond Tracee's specific use case
2. **Self-contained** - No imports from other Tracee packages
3. **Well documented** - All public functions and types should have clear documentation
4. **Tested** - Include unit tests for new functionality
5. **Package organization** - New code should be placed in internal packages (e.g., `common/hash/hash.go`) rather than directly under common (e.g., `common/hash.go`)

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
The common module should be completely self-contained and not depend on any external, non-standard packages. It should only import from Go's standard library.

### No Business Logic
This module **must not** contain any business logic specific to Tracee's core functionality. It should only provide generic utilities and types that could potentially be useful in other contexts.

### Minimal Dependencies
- Only Go standard library packages are allowed as dependencies
- No dependencies on other Tracee modules or packages

## Usage

### In Consumer code
```go
import "github.com/aquasecurity/tracee/common"
```

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

# Tracee Detectors

This module contains event detector implementations for Tracee's detector API.

## Detector Types

### Go Detectors (Built-in)

Go detectors in this module use automatic registration via `init()` functions:

```go
package detectors

func init() {
    register(&MyDetector{})
}

type MyDetector struct {
    // detector fields
}

// Implement detection.EventDetector interface methods
```

No manual registration list is needed - detectors are automatically discovered during package initialization.

### YAML Detectors

YAML detectors provide a declarative way to define threat detection and derived events without writing Go code.

**Example YAML detectors** are provided in the `yaml/` directory for reference.

**Runtime locations** for YAML detectors:
- `./detectors/` - Local directory (relative to working directory)
- `/etc/tracee/detectors/` - System-wide directory
- Custom path via `--detectors yaml-dir=/path/to/dir`

See `yaml/README.md` for YAML detector syntax and examples.

## Module Structure

- `registry.go` - Auto-registration system for Go detectors
- `example.go` - Example Go detector template
- `*.go` - Built-in Go detector implementations
- `yaml/` - Example YAML detectors (reference only, not loaded by default)

## Usage

Tracee's main package imports this module and calls `GetAllDetectors()` to retrieve all registered detectors:

```go
import "github.com/aquasecurity/tracee/detectors"

allDetectors := detectors.GetAllDetectors()
// Register detectors with the detector engine
```

## Adding a New Detector

### Go Detector

1. Create a new file (e.g., `my_detector.go`)
2. Implement the `detection.EventDetector` interface
3. Add `init()` function calling `register(&MyDetector{})`
4. The detector will automatically be included when the package is imported

### YAML Detector

1. Create a YAML file following the schema (see `yaml/` examples)
2. Place it in `./detectors/`, `/etc/tracee/detectors/`, or use `--detectors yaml-dir`
3. Tracee will automatically load it at runtime


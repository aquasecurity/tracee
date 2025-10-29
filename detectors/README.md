# Tracee Detectors

This module contains event detector implementations for Tracee's detector API.

## Auto-Registration Pattern

Detectors in this module use automatic registration via `init()` functions. Simply create a detector file and call `register()` in the `init()` function:

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

## Module Structure

- `registry.go` - Auto-registration system
- `example.go` - Example detector template and documentation
- Individual detector files (to be added)

## Usage

Tracee's main package imports this module and calls `GetAllDetectors()` to retrieve all registered detectors:

```go
import "github.com/aquasecurity/tracee/detectors"

allDetectors := detectors.GetAllDetectors()
// Register detectors with the detector engine
```

## Adding a New Detector

1. Create a new file (e.g., `my_detector.go`)
2. Implement the `detection.EventDetector` interface
3. Add `init()` function calling `register(&MyDetector{})`
4. The detector will automatically be included when the package is imported


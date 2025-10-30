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
- `example_detector.go` - Comprehensive example demonstrating all API features (build tag: `detectorexamples`)
- Individual detector files

## Usage

Tracee's main package imports this module and calls `GetAllDetectors()` to retrieve all registered detectors:

```go
import "github.com/aquasecurity/tracee/detectors"

allDetectors := detectors.GetAllDetectors()
// Register detectors with the detector engine
```

## Example Detectors

### Comprehensive Example: `example_detector.go`

A fully-featured example demonstrating all detector API capabilities:

- DataStore API usage (ContainerStore, SystemStore)
- Event filtering patterns (scope filters, data filters, version constraints)
- Conditional field population and enrichment
- Proper error handling with sentinel errors
- Auto-population features (Threat, DetectedFrom, ProcessAncestry)

**Note**: This detector is excluded from default builds using the `detectorexamples` build tag to prevent noise (triggers on all `execve` events).

To build with example detectors:

```bash
# Build Tracee with example detectors included (convenience target)
make tracee-with-examples

# Or manually override GO_TAGS_EBPF
make tracee GO_TAGS_EBPF="core,ebpf,lsmsupport,detectorexamples"
```

## Adding a New Detector

1. Create a new file (e.g., `my_detector.go`)
2. Implement the `detection.EventDetector` interface
3. Add `init()` function calling `register(&MyDetector{})`
4. The detector will automatically be included when the package is imported


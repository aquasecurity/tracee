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

**Example YAML detectors** are provided in the repository's `examples/detectors/yaml/` directory for reference. These are pure reference files meant to be copied and customized by users.

See the [YAML Detectors documentation](https://aquasecurity.github.io/tracee/latest/detectors/yaml-detectors/) for syntax, examples, and usage details.

## Module Structure

- `registry.go` - Auto-registration system for Go detectors
- `example_detector.go` - Comprehensive educational example (see below)
- `*.go` - Built-in Go detector implementations

## Usage

Tracee's main package imports this module and calls `GetAllDetectors()` to retrieve all registered detectors:

```go
import "github.com/aquasecurity/tracee/detectors"

allDetectors := detectors.GetAllDetectors()
// Register detectors with the detector engine
```

## Example Detector

### Comprehensive Example: `example_detector.go`

A fully-featured Go detector demonstrating all detector API capabilities:

- DataStore API usage (ContainerStore, SystemStore)
- Event filtering patterns (scope filters, data filters, version constraints)
- Conditional field population and enrichment
- Proper error handling with sentinel errors
- Auto-population features (Threat, DetectedFrom, ProcessAncestry)

**Usage:**

1. **For reference**: Read the code to learn detector patterns
2. **For testing**: Build Tracee with the example included:

```bash
# Build Tracee with example detectors included
make tracee-with-examples

# Or manually override GO_TAGS_EBPF
make tracee GO_TAGS_EBPF="core,ebpf,lsmsupport,detectorexamples"

# Run tracee and filter for the example detection
sudo ./dist/tracee -e example_detection --output json
```

**Note**: This detector is excluded from default builds using the `detectorexamples` build tag to prevent noise (it triggers on all `execve` events).

## Adding a New Detector

### Go Detector

1. Create a new file (e.g., `my_detector.go`)
2. Implement the `detection.EventDetector` interface
3. Add `init()` function calling `register(&MyDetector{})`
4. The detector will automatically be included when the package is imported

### YAML Detector

See the [YAML Detectors documentation](https://aquasecurity.github.io/tracee/latest/detectors/yaml-detectors/) for instructions on creating and deploying YAML detectors.


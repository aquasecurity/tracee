# Detector Testing Framework

A comprehensive testing framework for unit testing Tracee detectors (both Go and YAML).

## Two Testing Approaches

### 1. Simple Testing (`NewSimpleTest`) - Recommended for Most Tests
**Best for:** Unit testing detector logic, stateful detectors, event streams

- ✅ **Minimal setup** - just detector + logger
- ✅ **Direct `OnEvent()` calls** - no engine overhead
- ✅ **Perfect for stateful detectors** - test state across event streams
- ✅ **Fast** - synchronous, no goroutines
- ❌ No policy filtering, auto-population, or detector chaining

**Use when:** Testing detector logic, state management, or event processing

### 2. Full Harness (`NewTestHarness`) - For Integration Tests
**Best for:** Integration testing with Tracee components

- ✅ **Tests complete lifecycle** - registration, filtering, auto-population
- ✅ **Policy filters** - validates scope/data filters work correctly
- ✅ **Auto-population** - tests threat, detected_from, process_ancestry
- ✅ **Detector chains** - tests detector A → detector B composition
- ❌ Requires `make test-unit` (transitive libbpf dependencies)
- ❌ More setup overhead

**Use when:** Testing detector integration with policy engine or detector chaining

## Detector Implementation: DetectorOutput

Detectors return `[]detection.DetectorOutput` instead of `[]*v1beta1.Event`. This clarifies responsibilities:

```go
type DetectorOutput struct {
    Data          []*v1beta1.EventValue  // Detection findings (required)
    AutoPopulate  *AutoPopulateFields    // Override auto-population (optional)
    Threat        *v1beta1.Threat        // Override threat metadata (optional)
    AncestryDepth *uint32                // Override ancestry depth (optional)
}
```

**Detector responsibilities:**
- Extract relevant data from input event
- Return `Data` with detection-specific fields
- Optionally customize `AutoPopulate`, `Threat`, or `AncestryDepth` per detection

**Engine responsibilities:**
- Assign event ID and name from detector definition
- Clone workload/timestamp/policies from input event
- Apply auto-population (threat, detected_from, process_ancestry)
- Use `AncestryDepth` override if provided (priority: output > definition default of 5)

**Example:**

```go
func (d *MyDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
    pathname, found := v1beta1.GetData[string](event, "pathname")
    if !found || pathname != "/bin/nc" {
        return nil, nil // No detection
    }

    // Engine auto-populates Threat, DetectedFrom based on definition
    return []detection.DetectorOutput{{
        Data: []*v1beta1.EventValue{
            v1beta1.NewStringValue("binary_path", pathname),
            v1beta1.NewInt32Value("risk_score", 85),
        },
    }}, nil
}
```

## Quick Start

### Simple Testing (Recommended)

```go
package mydetector_test

import (
    "testing"
    "github.com/aquasecurity/tracee/tests/detectors"
)

func TestMyDetector(t *testing.T) {
    // Create simple test
    detector := &MyDetector{}
    test := detectors.NewSimpleTest(t, detector)
    defer test.Close()

    // Send event and verify output
    input := detectors.NewExecveEvent("/bin/nc")
    output := test.ExpectOutput(input)

    detectors.AssertFieldValue(t, output, "binary", "/bin/nc")
}

// Test stateful detector with event stream
func TestStatefulDetector(t *testing.T) {
    detector := &BruteForceDetector{threshold: 3}
    test := detectors.NewSimpleTest(t, detector)
    defer test.Close()

    // Send stream of events
    events := []*v1beta1.Event{
        createLoginEvent("192.168.1.1", false),
        createLoginEvent("192.168.1.1", false),
        createLoginEvent("192.168.1.1", false), // triggers detection
    }

    outputs := test.SendStream(events)
    assert.Len(t, outputs, 1)
}
```

### Full Harness Testing (For Integration)

```go
func TestMyDetectorWithFilters(t *testing.T) {
    // Create test harness with base events
    harness := detectors.NewTestHarness(t, events.Execve)

    // Register detector
    detector := &MyDetector{}
    harness.RegisterDetector(detector)

    // Test with policy filters applied
    input := detectors.NewExecveEvent("/bin/nc")
    outputs := harness.DispatchEvent(input)

    harness.AssertOutputCount(outputs, 1)
    harness.AssertThreatPopulated(outputs[0])
}
```

### Testing a YAML Detector

```go
func TestYAMLDetector(t *testing.T) {
    yaml := `
id: test-001
produced_event:
  name: suspicious_exec
requirements:
  events:
    - name: sched_process_exec
      data_filters:
        - pathname=/bin/nc
output:
  extract_fields:
    - name: binary_path
      source: data.pathname
`

    harness := detectors.NewYAMLTestHarness(t, yaml, events.SchedProcessExec)

    input := detectors.NewSchedProcessExecEvent("/bin/nc")
    outputs := harness.DispatchEvent(input)

    require.Len(t, outputs, 1)
    detectors.AssertFieldValue(t, outputs[0], "binary_path", "/bin/nc")
}
```

## Core Components

### TestHarness

The `TestHarness` provides a complete testing environment for detectors.

```go
type TestHarness struct {
    Engine      *detectors.Engine
    Context     context.Context
    T           *testing.T
    EventIDMap  map[string]events.ID
    nextEventID events.ID
}
```

**Key Methods:**

- `NewTestHarness(t *testing.T, selectedEvents ...events.ID) *TestHarness` - Creates a new harness
- `RegisterDetector(detector detection.EventDetector) error` - Registers a detector
- `DispatchEvent(event *v1beta1.Event) []*v1beta1.Event` - Dispatches an event and returns outputs
- `FindOutputByName(outputs []*v1beta1.Event, name string) *v1beta1.Event` - Finds output by name
- `AssertOutputCount(outputs []*v1beta1.Event, expected int)` - Asserts output count
- `AssertOutputEvent(output *v1beta1.Event, expectedName string)` - Asserts event name
- `AssertThreatPopulated(output *v1beta1.Event)` - Asserts threat field is populated
- `AssertDetectedFromPopulated(output *v1beta1.Event, inputEventName string)` - Asserts DetectedFrom field

## Event Builders

Event builders create test events with a fluent API.

### Basic Builders

```go
// Create execve event
event := detectors.NewExecveEvent("/bin/nc")

// Create sched_process_exec event
event := detectors.NewSchedProcessExecEvent("/usr/bin/cat")

// Create openat event
event := detectors.NewOpenatEvent("/tmp/file", "O_RDONLY")

// Create network event
event := detectors.NewNetworkEvent("192.168.1.1", "10.0.0.1")
```

### Event Options

Customize events using options:

```go
event := detectors.NewExecveEvent("/bin/nc",
    detectors.WithWorkloadProcess(1234, "nc"),
    detectors.WithContainer("abc123", "test-container"),
    detectors.WithK8s("app-pod", "production"),
    detectors.WithTimestamp(time.Now()),
    detectors.WithData(
        v1beta1.NewStringValue("custom_field", "value"),
    ),
)
```

**Available Options:**

- `WithWorkloadProcess(pid uint32, comm string)` - Add process information
- `WithContainer(id, name string)` - Add container information
- `WithK8s(podName, namespace string)` - Add Kubernetes information
- `WithTimestamp(ts time.Time)` - Set custom timestamp
- `WithData(values ...*v1beta1.EventValue)` - Add custom data fields
- `WithEventID(id events.ID)` - Set custom event ID
- `WithEventName(name string)` - Set custom event name

## Assertion Helpers

### Field Assertions

```go
// Assert field has expected value
detectors.AssertFieldValue(t, event, "pathname", "/bin/nc")

// Assert field exists
detectors.AssertFieldExists(t, event, "pathname")

// Assert field is missing
detectors.AssertFieldMissing(t, event, "optional_field")
```

### Threat Assertions

```go
// Assert threat severity
detectors.AssertThreatSeverity(t, event, v1beta1.Severity_HIGH)

// Assert MITRE technique
detectors.AssertMitreTechnique(t, event, "T1059")

// Assert MITRE tactic
detectors.AssertMitreTactic(t, event, "Execution")
```

### Workload Assertions

```go
// Assert process PID
detectors.AssertProcessPID(t, event, 1234)

// Assert container ID
detectors.AssertContainerID(t, event, "abc123")

// Assert Kubernetes pod name
detectors.AssertK8sPodName(t, event, "app-pod")
```

## YAML Detector Testing

### Loading YAML Detectors

```go
// Load from string
detector := detectors.LoadYAMLDetectorFromString(t, yamlContent)

// Load from file
detector := detectors.LoadYAMLDetectorFromFile(t, "path/to/detector.yaml")

// Create harness with YAML detector pre-loaded
harness := detectors.NewYAMLTestHarness(t, yamlContent, events.SchedProcessExec)

// Create temporary YAML file
tmpFile := detectors.CreateTempYAMLDetector(t, yamlContent)
```

### Testing YAML Filters

```go
func TestYAMLFilters(t *testing.T) {
    yaml := `
id: test-filters
produced_event:
  name: filtered_event
requirements:
  events:
    - name: sched_process_exec
      scope_filters:
        - container=true
      data_filters:
        - pathname=/bin/nc
`

    harness := detectors.NewYAMLTestHarness(t, yaml, events.SchedProcessExec)

    // Test matching event
    input := detectors.NewSchedProcessExecEvent("/bin/nc",
        detectors.WithContainer("abc", "test"))
    outputs := harness.DispatchEvent(input)
    require.Len(t, outputs, 1)

    // Test non-matching event (no container)
    input = detectors.NewSchedProcessExecEvent("/bin/nc")
    outputs = harness.DispatchEvent(input)
    require.Len(t, outputs, 0)
}
```

## Detector Chaining

Test multi-level detector chains by dispatching outputs to the next level.

```go
func TestDetectorChain(t *testing.T) {
    harness := detectors.NewTestHarness(t, events.SchedProcessExec)

    // Register level 1 detector
    level1 := detectors.LoadYAMLDetectorFromString(t, level1YAML)
    harness.RegisterDetector(level1)

    // Register level 2 detector (consumes level1 output)
    level2 := detectors.LoadYAMLDetectorFromString(t, level2YAML)
    harness.RegisterDetector(level2)

    // Trigger chain
    input := detectors.NewSchedProcessExecEvent("/bin/nc",
        detectors.WithContainer("abc123", "test"))

    // Level 1
    level1Outputs := harness.DispatchEvent(input)
    require.Len(t, level1Outputs, 1)

    // Level 2
    level2Outputs := harness.DispatchEvent(level1Outputs[0])
    require.Len(t, level2Outputs, 1)

    // Verify final output
    detectors.AssertFieldValue(t, level2Outputs[0], "container_id", "abc123")
}
```

## Testing Patterns

### Pattern 1: Positive and Negative Tests

```go
func TestDetector(t *testing.T) {
    harness := detectors.NewTestHarness(t, events.Execve)
    harness.RegisterDetector(&MyDetector{})

    t.Run("DetectsMatchingEvent", func(t *testing.T) {
        input := detectors.NewExecveEvent("/bin/nc")
        outputs := harness.DispatchEvent(input)
        harness.AssertOutputCount(outputs, 1)
    })

    t.Run("IgnoresNonMatchingEvent", func(t *testing.T) {
        input := detectors.NewExecveEvent("/bin/ls")
        outputs := harness.DispatchEvent(input)
        harness.AssertOutputCount(outputs, 0)
    })
}
```

### Pattern 2: Testing Auto-Population

```go
func TestAutoPopulation(t *testing.T) {
    harness := detectors.NewTestHarness(t, events.Execve)

    // Detector with auto-population enabled
    detector := &MyDetector{
        autoPopulate: detection.AutoPopulateFields{
            Threat:       true,
            DetectedFrom: true,
        },
    }
    harness.RegisterDetector(detector)

    input := detectors.NewExecveEvent("/bin/nc")
    outputs := harness.DispatchEvent(input)

    // Verify auto-populated fields
    harness.AssertThreatPopulated(outputs[0])
    harness.AssertDetectedFromPopulated(outputs[0], "execve")
}
```

### Pattern 3: Testing Field Extraction

```go
func TestFieldExtraction(t *testing.T) {
    yaml := `
id: test-extraction
produced_event:
  name: extracted_event
  fields:
    - name: binary_path
      type: string
    - name: pid
      type: uint32
requirements:
  events:
    - name: sched_process_exec
output:
  extract_fields:
    - name: binary_path
      source: data.pathname
    - name: pid
      source: workload.process.pid.value
`

    harness := detectors.NewYAMLTestHarness(t, yaml, events.SchedProcessExec)

    input := detectors.NewSchedProcessExecEvent("/bin/nc",
        detectors.WithWorkloadProcess(1234, "nc"))

    outputs := harness.DispatchEvent(input)

    detectors.AssertFieldValue(t, outputs[0], "binary_path", "/bin/nc")
    detectors.AssertFieldValue(t, outputs[0], "pid", uint32(1234))
}
```

## Best Practices

### 1. Use Descriptive Test Names

```go
t.Run("DetectsNetcatInProductionContainer", func(t *testing.T) {
    // ...
})
```

### 2. Test Both Positive and Negative Cases

Always test that your detector:
- Fires when it should (positive case)
- Doesn't fire when it shouldn't (negative case)

### 3. Verify All Output Fields

Don't just check that an event was produced - verify all expected fields:

```go
outputs := harness.DispatchEvent(input)
require.Len(t, outputs, 1)
detectors.AssertFieldValue(t, outputs[0], "field1", "expected1")
detectors.AssertFieldValue(t, outputs[0], "field2", "expected2")
harness.AssertThreatPopulated(outputs[0])
```

### 4. Test Filter Combinations

Test different combinations of scope and data filters:

```go
t.Run("ContainerWithSuspiciousBinary", func(t *testing.T) {
    // Both filters match
})

t.Run("ContainerWithNormalBinary", func(t *testing.T) {
    // Scope matches, data doesn't
})

t.Run("HostWithSuspiciousBinary", func(t *testing.T) {
    // Data matches, scope doesn't
})
```

### 5. Use Table-Driven Tests for Multiple Scenarios

```go
func TestMultipleScenarios(t *testing.T) {
    tests := []struct {
        name     string
        pathname string
        wantFire bool
    }{
        {"Netcat", "/bin/nc", true},
        {"Ncat", "/usr/bin/ncat", true},
        {"Socat", "/usr/bin/socat", true},
        {"Ls", "/bin/ls", false},
    }

    harness := detectors.NewTestHarness(t, events.Execve)
    harness.RegisterDetector(&MyDetector{})

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            input := detectors.NewExecveEvent(tt.pathname)
            outputs := harness.DispatchEvent(input)

            if tt.wantFire {
                harness.AssertOutputCount(outputs, 1)
            } else {
                harness.AssertOutputCount(outputs, 0)
            }
        })
    }
}
```

## Examples

See the `examples/` directory for complete working examples:

- `simple_test.go` - Basic Go detector testing
- `yaml_test.go` - YAML detector testing with filters
- `chain_test.go` - Multi-level detector chain testing

## Troubleshooting

### Event Not Dispatched to Detector

**Problem**: `harness.DispatchEvent()` returns empty array.

**Solutions**:
1. Ensure you passed the correct base event ID to `NewTestHarness()`:
   ```go
   harness := detectors.NewTestHarness(t, events.SchedProcessExec) // Not events.Execve
   ```

2. Check that your detector's requirements match the input event name

3. Verify filters are correctly specified and match the input event

### Event ID Already Exists Error

**Problem**: `definition id already exists` error.

**Solution**: Each test gets a unique event ID range. This error usually means you're running tests in parallel that share global state. The framework handles this automatically, but if you see this error, ensure you're creating a new `TestHarness` for each test.

### Field Not Found in Event Data

**Problem**: `AssertFieldValue` fails with "field not found".

**Solutions**:
1. Check the field name matches exactly (case-sensitive)
2. Verify the detector actually extracts/populates that field
3. Use `AssertFieldExists` first to debug which fields are present

### YAML Detector Not Loading

**Problem**: `LoadYAMLDetectorFromString` fails.

**Solutions**:
1. Check YAML syntax (indentation, colons, etc.)
2. Verify all required fields are present (`id`, `produced_event`, `requirements`)
3. Check that event names in `requirements.events` are valid Tracee events

## Performance Considerations

- **Fast**: No eBPF, no kernel interaction, pure Go
- **Isolated**: Each `TestHarness` is independent
- **Parallel**: Tests can run in parallel (each gets unique event IDs)
- **Lightweight**: Minimal dependencies, just the detector engine

## Comparison with Integration Tests

| Feature | Unit Tests (This Framework) | Integration Tests |
|---------|----------------------------|-------------------|
| Speed | Fast (~ms per test) | Slow (~seconds per test) |
| eBPF Required | No | Yes |
| Root Required | No | Yes |
| Scope | Single detector | Full Tracee pipeline |
| Use Case | Detector logic testing | End-to-end validation |

**Recommendation**: Use unit tests for detector logic, integration tests for full system validation.


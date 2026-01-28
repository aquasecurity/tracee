# Detector Testing Framework

A lightweight framework for testing detector integration with the Tracee engine.

## When to Use

| Approach | Use Case |
|----------|----------|
| **Direct testing** | Unit test detector logic via `OnEvent()` directly (see `detectors/*_test.go`) |
| **TestHarness** | Integration testing with engine (policy filtering, auto-population, detector chains) |

For most detectors, direct testing is sufficient. Use TestHarness when you need to test:
- Event ID allocation and registration
- Policy filtering behavior
- Auto-population of Threat/DetectedFrom fields
- Detector chaining (output of detector A feeds detector B)

## Quick Start

### TestHarness (Engine Integration)

```go
func TestMyDetector(t *testing.T) {
    // Create harness with base events your detector consumes
    harness := detectors.NewTestHarness(t, events.Execve)

    // Register your detector
    detector := &MyDetector{}
    require.NoError(t, harness.RegisterDetector(detector))

    // Create input event and dispatch
    input := &v1beta1.Event{
        Id:   v1beta1.EventId(events.Execve),
        Name: "execve",
        Data: []*v1beta1.EventValue{
            v1beta1.NewStringValue("pathname", "/bin/nc"),
        },
    }

    outputs := harness.DispatchEvent(input)

    // Verify outputs
    require.Len(t, outputs, 1)
    harness.AssertThreatPopulated(outputs[0])
    harness.AssertDetectedFromPopulated(outputs[0], "execve")
}
```

### YAML Detector Testing

```go
func TestYAMLDetector(t *testing.T) {
    yaml := `
id: test-detector
produced_event:
  name: suspicious_exec
requirements:
  events:
    - name: sched_process_exec
      data_filters:
        - pathname=/bin/nc
output:
  fields:
    - name: binary_path
      expression: getEventData("pathname")
`
    harness := detectors.NewYAMLTestHarness(t, yaml, events.SchedProcessExec)

    input := &v1beta1.Event{
        Id:   v1beta1.EventId(events.SchedProcessExec),
        Name: "sched_process_exec",
        Data: []*v1beta1.EventValue{
            v1beta1.NewStringValue("pathname", "/bin/nc"),
        },
    }

    outputs := harness.DispatchEvent(input)
    require.Len(t, outputs, 1)
}
```

## See Also

- **Direct detector tests**: `detectors/*_test.go` - examples of testing detector logic directly
- **Detector implementations**: `detectors/*.go` - Go detector examples
- **YAML detectors**: `pkg/detectors/yaml/*.yaml` - YAML detector examples

package examples

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/tests/detectors"
)

// TestYAMLDetector demonstrates YAML detector testing
func TestYAMLDetector(t *testing.T) {
	yamlContent := `
id: yaml-suspicious-exec
produced_event:
  name: suspicious_execution
  version: 1.0.0
  description: Detects execution of suspicious binaries
  tags:
    - execution
    - defense-evasion
  fields:
    - name: binary_path
      type: string
    - name: binary_name
      type: string

requirements:
  min_tracee_version: 0.0.0
  events:
    - name: sched_process_exec
      dependency: required
      data_filters:
        - pathname=/bin/nc
        - pathname=/usr/bin/ncat
        - pathname=/usr/bin/socat

threat:
  name: Suspicious Binary Execution
  severity: medium
  description: Execution of networking tool commonly used for attacks
  mitre:
    technique:
      id: T1059
      name: Command and Scripting Interpreter
    tactic:
      name: Execution

auto_populate:
  threat: true
  detected_from: true

output:
  fields:
    - name: binary_path
      expression: getData("pathname")
    - name: binary_name
      expression: workload.process.thread.name
`

	// Create harness with YAML detector loaded
	harness := detectors.NewYAMLTestHarness(t, yamlContent, events.SchedProcessExec)

	t.Run("DetectsSuspiciousBinary", func(t *testing.T) {
		// Create input event
		input := detectors.NewSchedProcessExecEvent("/bin/nc",
			detectors.WithWorkloadProcess(1234, "nc"))

		// Dispatch to detector
		outputs := harness.DispatchEvent(input)

		// Verify detection
		require.Len(t, outputs, 1)
		assert.Equal(t, "suspicious_execution", outputs[0].Name)

		// Verify extracted fields
		detectors.AssertFieldValue(t, outputs[0], "binary_path", "/bin/nc")
		detectors.AssertFieldValue(t, outputs[0], "binary_name", "nc")

		// Verify auto-populated fields
		harness.AssertThreatPopulated(outputs[0])
		harness.AssertDetectedFromPopulated(outputs[0], "sched_process_exec")
		detectors.AssertThreatSeverity(t, outputs[0], v1beta1.Severity_MEDIUM)
		detectors.AssertMitreTechnique(t, outputs[0], "T1059")
	})

	t.Run("IgnoresNonMatchingBinaries", func(t *testing.T) {
		// Create input event for non-suspicious binary
		input := detectors.NewSchedProcessExecEvent("/usr/bin/cat")

		// Dispatch to detector
		outputs := harness.DispatchEvent(input)

		// Verify no detection
		require.Len(t, outputs, 0)
	})
}

// TestYAMLDetectorWithFilters demonstrates YAML detector with scope filters
func TestYAMLDetectorWithFilters(t *testing.T) {
	yamlContent := `
id: yaml-container-exec
produced_event:
  name: container_suspicious_exec
  version: 1.0.0
  description: Detects suspicious execution in containers
  fields:
    - name: binary_path
      type: string
    - name: container_id
      type: string

requirements:
  events:
    - name: sched_process_exec
      dependency: required
      scope_filters:
        - container
      data_filters:
        - pathname=/bin/nc

output:
  fields:
    - name: binary_path
      expression: getData("pathname")
    - name: container_id
      expression: workload.container.id
`

	harness := detectors.NewYAMLTestHarness(t, yamlContent, events.SchedProcessExec)

	t.Run("DetectsInContainer", func(t *testing.T) {
		// Create input event with container context
		input := detectors.NewSchedProcessExecEvent("/bin/nc",
			detectors.WithContainer("abc123", "test-container"))

		// Dispatch to detector
		outputs := harness.DispatchEvent(input)

		// Verify detection
		require.Len(t, outputs, 1)
		detectors.AssertFieldValue(t, outputs[0], "binary_path", "/bin/nc")
		detectors.AssertFieldValue(t, outputs[0], "container_id", "abc123")
	})

	t.Run("IgnoresNonContainerExecution", func(t *testing.T) {
		// Create input event WITHOUT container context
		input := detectors.NewSchedProcessExecEvent("/bin/nc")

		// Dispatch to detector
		outputs := harness.DispatchEvent(input)

		// Verify no detection (scope filter doesn't match)
		require.Len(t, outputs, 0)
	})
}

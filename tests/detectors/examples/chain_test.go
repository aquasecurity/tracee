package examples

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/tests/detectors"
)

// TestDetectorChain demonstrates testing detector chains
func TestDetectorChain(t *testing.T) {
	// Level 1: Base detection - identifies suspicious binary execution
	level1YAML := `
id: chain-level1
produced_event:
  name: suspicious_exec_detected
  version: 1.0.0
  description: Base detection of suspicious binary
  fields:
    - name: binary_path
      type: string

requirements:
  events:
    - name: sched_process_exec
      dependency: required
      data_filters:
        - pathname=/bin/nc
        - pathname=/usr/bin/ncat

auto_populate:
  detected_from: true

output:
  fields:
    - name: binary_path
      expression: getData("pathname")
`

	// Level 2: Context enrichment - adds container context
	level2YAML := `
id: chain-level2
produced_event:
  name: chain_container_suspicious_exec
  version: 1.0.0
  description: Suspicious execution in container
  fields:
    - name: binary_path
      type: string
    - name: container_id
      type: string
    - name: container_name
      type: string

requirements:
  events:
    - name: suspicious_exec_detected
      dependency: required
      scope_filters:
        - container

threat:
  name: Container Suspicious Execution
  severity: high
  description: Suspicious binary executed in container
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
      expression: getData("binary_path")
    - name: container_id
      expression: workload.container.id
    - name: container_name
      expression: workload.container.name
`

	// Create harness
	harness := detectors.NewTestHarness(t, events.SchedProcessExec)

	// Register level 1 detector
	level1 := detectors.LoadYAMLDetectorFromString(t, level1YAML)
	require.NoError(t, harness.RegisterDetector(level1))

	// Register level 2 detector
	level2 := detectors.LoadYAMLDetectorFromString(t, level2YAML)
	require.NoError(t, harness.RegisterDetector(level2))

	t.Run("TwoLevelChain", func(t *testing.T) {
		// Create input event with container context
		input := detectors.NewSchedProcessExecEvent("/bin/nc",
			detectors.WithContainer("abc123", "test-container"))

		// Dispatch to level 1
		level1Outputs := harness.DispatchEvent(input)
		require.Len(t, level1Outputs, 1)
		assert.Equal(t, "suspicious_exec_detected", level1Outputs[0].Name)
		detectors.AssertFieldValue(t, level1Outputs[0], "binary_path", "/bin/nc")

		// Dispatch level 1 output to level 2
		level2Outputs := harness.DispatchEvent(level1Outputs[0])
		require.Len(t, level2Outputs, 1)
		assert.Equal(t, "chain_container_suspicious_exec", level2Outputs[0].Name)

		// Verify level 2 output
		detectors.AssertFieldValue(t, level2Outputs[0], "binary_path", "/bin/nc")
		detectors.AssertFieldValue(t, level2Outputs[0], "container_id", "abc123")
		detectors.AssertFieldValue(t, level2Outputs[0], "container_name", "test-container")

		// Verify auto-population
		harness.AssertThreatPopulated(level2Outputs[0])
		harness.AssertDetectedFromPopulated(level2Outputs[0], "suspicious_exec_detected")
		detectors.AssertThreatSeverity(t, level2Outputs[0], v1beta1.Severity_HIGH)

		// Verify DetectedFrom chain preservation
		require.NotNil(t, level2Outputs[0].DetectedFrom, "Level 2 should have DetectedFrom")
		assert.Equal(t, "suspicious_exec_detected", level2Outputs[0].DetectedFrom.Name, "Immediate parent should be level 1")

		// Verify chain to root (original execve event)
		require.NotNil(t, level2Outputs[0].DetectedFrom.Parent, "DetectedFrom should have parent")
		assert.Equal(t, "sched_process_exec", level2Outputs[0].DetectedFrom.Parent.Name, "Root should be sched_process_exec")

		// Verify root has no parent
		assert.Nil(t, level2Outputs[0].DetectedFrom.Parent.Parent, "Root should have no parent")

		// Verify chain depth
		assert.Equal(t, 2, v1beta1.GetChainDepth(level2Outputs[0]), "Chain should have depth 2")
	})

	t.Run("ChainBreaksWithoutContainer", func(t *testing.T) {
		// Create input event WITHOUT container context
		input := detectors.NewSchedProcessExecEvent("/bin/nc")

		// Dispatch to level 1
		level1Outputs := harness.DispatchEvent(input)
		require.Len(t, level1Outputs, 1)

		// Dispatch level 1 output to level 2
		// Level 2 should NOT fire because scope filter (container=true) doesn't match
		level2Outputs := harness.DispatchEvent(level1Outputs[0])
		require.Len(t, level2Outputs, 0)
	})
}

// TestThreeLevelChain demonstrates a more complex 3-level chain
func TestThreeLevelChain(t *testing.T) {
	// Level 1: Base pattern
	level1YAML := `
id: chain3-level1
produced_event:
  name: cryptominer_execution
  version: 1.0.0
  fields:
    - name: binary_path
      type: string
requirements:
  events:
    - name: sched_process_exec
      data_filters:
        - pathname=/usr/bin/xmrig
        - pathname=/tmp/miner
auto_populate:
  detected_from: true
output:
  fields:
    - name: binary_path
      expression: getData("pathname")
`

	// Level 2: Add container context
	level2YAML := `
id: chain3-level2
produced_event:
  name: cryptominer_in_container
  version: 1.0.0
  fields:
    - name: binary_path
      type: string
    - name: container_id
      type: string
requirements:
  events:
    - name: cryptominer_execution
      scope_filters:
        - container
auto_populate:
  detected_from: true
output:
  fields:
    - name: binary_path
      expression: getData("binary_path")
    - name: container_id
      expression: workload.container.id
`

	// Level 3: Add production environment context
	level3YAML := `
id: chain3-level3
produced_event:
  name: production_cryptominer_alert
  version: 1.0.0
  fields:
    - name: binary_path
      type: string
    - name: container_id
      type: string
    - name: namespace
      type: string
requirements:
  events:
    - name: cryptominer_in_container
threat:
  name: Production Cryptominer Alert
  severity: critical
  description: Cryptominer detected in production container
auto_populate:
  threat: true
  detected_from: true
output:
  fields:
    - name: binary_path
      expression: getData("binary_path")
    - name: container_id
      expression: getData("container_id")
    - name: namespace
      expression: workload.k8s.namespace.name
`

	// Create harness and register all detectors
	harness := detectors.NewTestHarness(t, events.SchedProcessExec)

	level1 := detectors.LoadYAMLDetectorFromString(t, level1YAML)
	require.NoError(t, harness.RegisterDetector(level1))

	level2 := detectors.LoadYAMLDetectorFromString(t, level2YAML)
	require.NoError(t, harness.RegisterDetector(level2))

	level3 := detectors.LoadYAMLDetectorFromString(t, level3YAML)
	require.NoError(t, harness.RegisterDetector(level3))

	t.Run("FullChainInProduction", func(t *testing.T) {
		// Create input with full context
		input := detectors.NewSchedProcessExecEvent("/usr/bin/xmrig",
			detectors.WithContainer("prod-123", "app-container"),
			detectors.WithK8s("app-pod", "production"))

		// Level 1
		level1Outputs := harness.DispatchEvent(input)
		require.Len(t, level1Outputs, 1)
		assert.Equal(t, "cryptominer_execution", level1Outputs[0].Name)

		// Level 2
		level2Outputs := harness.DispatchEvent(level1Outputs[0])
		require.Len(t, level2Outputs, 1)
		assert.Equal(t, "cryptominer_in_container", level2Outputs[0].Name)

		// Level 3
		level3Outputs := harness.DispatchEvent(level2Outputs[0])
		require.Len(t, level3Outputs, 1)
		assert.Equal(t, "production_cryptominer_alert", level3Outputs[0].Name)

		// Verify final output
		detectors.AssertFieldValue(t, level3Outputs[0], "binary_path", "/usr/bin/xmrig")
		detectors.AssertFieldValue(t, level3Outputs[0], "container_id", "prod-123")
		detectors.AssertFieldValue(t, level3Outputs[0], "namespace", "production")
		detectors.AssertThreatSeverity(t, level3Outputs[0], v1beta1.Severity_CRITICAL)

		// Verify 3-level DetectedFrom chain
		require.NotNil(t, level3Outputs[0].DetectedFrom, "Level 3 should have DetectedFrom")
		assert.Equal(t, "cryptominer_in_container", level3Outputs[0].DetectedFrom.Name, "Immediate parent should be level 2")

		// Verify level 2 is in the chain
		require.NotNil(t, level3Outputs[0].DetectedFrom.Parent, "Level 2 should have parent")
		assert.Equal(t, "cryptominer_execution", level3Outputs[0].DetectedFrom.Parent.Name, "Level 2 parent should be level 1")

		// Verify level 1 (root) is in the chain
		require.NotNil(t, level3Outputs[0].DetectedFrom.Parent.Parent, "Level 1 should have parent")
		assert.Equal(t, "sched_process_exec", level3Outputs[0].DetectedFrom.Parent.Parent.Name, "Root should be sched_process_exec")

		// Verify root has no parent
		assert.Nil(t, level3Outputs[0].DetectedFrom.Parent.Parent.Parent, "Root should have no parent")

		// Verify chain depth
		assert.Equal(t, 3, v1beta1.GetChainDepth(level3Outputs[0]), "Chain should have depth 3")

		// Test helper functions
		chain := v1beta1.GetDetectionChain(level3Outputs[0])
		require.Len(t, chain, 3, "Chain should have 3 elements")
		assert.Equal(t, "cryptominer_in_container", chain[0].Name, "Chain[0] should be immediate parent")
		assert.Equal(t, "cryptominer_execution", chain[1].Name, "Chain[1] should be level 1")
		assert.Equal(t, "sched_process_exec", chain[2].Name, "Chain[2] should be root")

		root := v1beta1.GetRootDetection(level3Outputs[0])
		require.NotNil(t, root, "Root detection should exist")
		assert.Equal(t, "sched_process_exec", root.Name, "Root should be original event")
	})

	t.Run("ChainWithDifferentNamespace", func(t *testing.T) {
		// Create input with dev namespace - chain still fires (no namespace filtering)
		input := detectors.NewSchedProcessExecEvent("/usr/bin/xmrig",
			detectors.WithContainer("dev-456", "app-container"),
			detectors.WithK8s("app-pod", "development"))

		// Level 1
		level1Outputs := harness.DispatchEvent(input)
		require.Len(t, level1Outputs, 1)

		// Level 2
		level2Outputs := harness.DispatchEvent(level1Outputs[0])
		require.Len(t, level2Outputs, 1)

		// Level 3 fires for all level 2 events
		level3Outputs := harness.DispatchEvent(level2Outputs[0])
		require.Len(t, level3Outputs, 1)

		// Verify namespace was extracted correctly
		detectors.AssertFieldValue(t, level3Outputs[0], "namespace", "development")
	})
}

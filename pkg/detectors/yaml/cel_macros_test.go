package yaml

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/aquasecurity/tracee/api/v1beta1"
)

// Test that the simplified getData("field") syntax works via macro
func TestGetDataMacro(t *testing.T) {
	env, err := createCELEnvironment()
	require.NoError(t, err, "Failed to create CEL environment")

	// Test expression: getData("pathname")
	prog, err := CompileExpression(env, `getData("pathname")`)
	require.NoError(t, err, "Failed to compile getData macro expression")

	// Create test event
	event := &v1beta1.Event{
		Name: "test_event",
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", "/etc/shadow"),
		},
	}

	// Evaluate
	result, err := EvaluateExpression(prog, event, 0)
	require.NoError(t, err, "Failed to evaluate expression")

	// Verify result
	assert.Equal(t, "/etc/shadow", result)
}

// Test hasData macro
func TestHasDataMacro(t *testing.T) {
	env, err := createCELEnvironment()
	require.NoError(t, err, "Failed to create CEL environment")

	prog, err := CompileExpression(env, `hasData("pathname")`)
	require.NoError(t, err, "Failed to compile hasData macro expression")

	event := &v1beta1.Event{
		Name: "test_event",
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", "/etc/shadow"),
		},
	}

	result, err := EvaluateExpression(prog, event, 0)
	require.NoError(t, err, "Failed to evaluate expression")
	assert.Equal(t, true, result)

	// Test with missing field
	prog2, err := CompileExpression(env, `hasData("missing_field")`)
	require.NoError(t, err, "Failed to compile hasData macro expression")

	result2, err := EvaluateExpression(prog2, event, 0)
	require.NoError(t, err, "Failed to evaluate expression")
	assert.Equal(t, false, result2)
}

// Test getDataInt macro
func TestGetDataIntMacro(t *testing.T) {
	env, err := createCELEnvironment()
	require.NoError(t, err, "Failed to create CEL environment")

	prog, err := CompileExpression(env, `getData("uid")`)
	require.NoError(t, err, "Failed to compile getData for int32")

	event := &v1beta1.Event{
		Name: "test_event",
		Data: []*v1beta1.EventValue{
			v1beta1.NewInt32Value("uid", 1000),
		},
	}

	result, err := EvaluateExpression(prog, event, 0)
	require.NoError(t, err, "Failed to evaluate expression")
	assert.Equal(t, int64(1000), result) // CEL converts int32 to int64
}

// Test getDataUInt macro
func TestGetDataUIntMacro(t *testing.T) {
	env, err := createCELEnvironment()
	require.NoError(t, err, "Failed to create CEL environment")

	prog, err := CompileExpression(env, `getData("pid")`)
	require.NoError(t, err, "Failed to compile getData for uint32")

	event := &v1beta1.Event{
		Name: "test_event",
		Data: []*v1beta1.EventValue{
			v1beta1.NewUInt32Value("pid", 12345),
		},
	}

	result, err := EvaluateExpression(prog, event, 0)
	require.NoError(t, err, "Failed to evaluate expression")
	assert.Equal(t, uint64(12345), result) // CEL converts uint32 to uint64
}

// Test getData with numeric comparisons (dynamic typing in action)
func TestGetDataNumericComparison(t *testing.T) {
	env, err := createCELEnvironment()
	require.NoError(t, err, "Failed to create CEL environment")

	// Condition: getData("pid") > 1000
	prog, err := CompileCondition(env, `getData("pid") > 1000`)
	require.NoError(t, err, "Failed to compile numeric condition")

	event := &v1beta1.Event{
		Name: "test_event",
		Data: []*v1beta1.EventValue{
			v1beta1.NewUInt32Value("pid", 12345),
		},
	}

	result, err := EvaluateCondition(prog, event, 0)
	require.NoError(t, err, "Failed to evaluate numeric condition")
	assert.True(t, result)
}

// Test that both unary and binary forms work (macro expands unary to binary)
func TestGetDataBothCallForms(t *testing.T) {
	env, err := createCELEnvironment()
	require.NoError(t, err, "Failed to create CEL environment")

	// Binary form: getData(event, "pathname")
	prog, err := CompileExpression(env, `getData(event, "pathname")`)
	require.NoError(t, err, "Failed to compile getData binary expression")

	event := &v1beta1.Event{
		Name: "test_event",
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", "/etc/shadow"),
		},
	}

	result, err := EvaluateExpression(prog, event, 0)
	require.NoError(t, err, "Failed to evaluate expression")
	assert.Equal(t, "/etc/shadow", result)
}

// Test macro in complex expressions
func TestGetDataMacroInExpression(t *testing.T) {
	env, err := createCELEnvironment()
	require.NoError(t, err, "Failed to create CEL environment")

	// Complex expression: getData("pathname").startsWith("/etc")
	prog, err := CompileExpression(env, `getData("pathname").startsWith("/etc")`)
	require.NoError(t, err, "Failed to compile complex expression")

	event := &v1beta1.Event{
		Name: "test_event",
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", "/etc/shadow"),
		},
	}

	result, err := EvaluateExpression(prog, event, 0)
	require.NoError(t, err, "Failed to evaluate expression")
	assert.Equal(t, true, result)
}

// Test macro with conditions
func TestGetDataMacroInCondition(t *testing.T) {
	env, err := createCELEnvironment()
	require.NoError(t, err, "Failed to create CEL environment")

	// Condition: hasData("pathname") && getData("pathname") == "/etc/shadow"
	prog, err := CompileCondition(env, `hasData("pathname") && getData("pathname") == "/etc/shadow"`)
	require.NoError(t, err, "Failed to compile condition")

	event := &v1beta1.Event{
		Name: "test_event",
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", "/etc/shadow"),
		},
	}

	result, err := EvaluateCondition(prog, event, 0)
	require.NoError(t, err, "Failed to evaluate condition")
	assert.True(t, result)
}

// Test top-level workload variable (no "event." prefix)
func TestWorkloadTopLevelVariable(t *testing.T) {
	env, err := createCELEnvironment()
	require.NoError(t, err, "Failed to create CEL environment")

	// Expression: workload.container.id (no "event." prefix!)
	prog, err := CompileExpression(env, `workload.container.id`)
	require.NoError(t, err, "Failed to compile expression")

	event := &v1beta1.Event{
		Name: "test_event",
		Workload: &v1beta1.Workload{
			Container: &v1beta1.Container{
				Id: "test-container-123",
			},
		},
	}

	result, err := EvaluateExpression(prog, event, 0)
	require.NoError(t, err, "Failed to evaluate expression")
	assert.Equal(t, "test-container-123", result)
}

// Test workload condition
func TestWorkloadInCondition(t *testing.T) {
	env, err := createCELEnvironment()
	require.NoError(t, err, "Failed to create CEL environment")

	// Condition: workload.container.id != ""
	prog, err := CompileCondition(env, `workload.container.id != ""`)
	require.NoError(t, err, "Failed to compile condition")

	event := &v1beta1.Event{
		Name: "test_event",
		Workload: &v1beta1.Workload{
			Container: &v1beta1.Container{
				Id: "test-container",
			},
		},
	}

	result, err := EvaluateCondition(prog, event, 0)
	require.NoError(t, err, "Failed to evaluate condition")
	assert.True(t, result)
}

// Test combined: simplified getData + top-level workload
func TestCombinedSimplifiedSyntax(t *testing.T) {
	env, err := createCELEnvironment()
	require.NoError(t, err, "Failed to create CEL environment")

	// Condition: hasData("pathname") && workload.container.id != ""
	prog, err := CompileCondition(env, `hasData("pathname") && workload.container.id != ""`)
	require.NoError(t, err, "Failed to compile condition")

	event := &v1beta1.Event{
		Name: "test_event",
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", "/etc/shadow"),
		},
		Workload: &v1beta1.Workload{
			Container: &v1beta1.Container{
				Id: "test-container",
			},
		},
	}

	result, err := EvaluateCondition(prog, event, 0)
	require.NoError(t, err, "Failed to evaluate condition")
	assert.True(t, result)
}

// Test workload.process.pid access
func TestWorkloadProcessAccess(t *testing.T) {
	env, err := createCELEnvironment()
	require.NoError(t, err, "Failed to create CEL environment")

	// Expression: workload.process.pid
	prog, err := CompileExpression(env, `workload.process.pid`)
	require.NoError(t, err, "Failed to compile expression")

	event := &v1beta1.Event{
		Name: "test_event",
		Workload: &v1beta1.Workload{
			Process: &v1beta1.Process{
				Pid: wrapperspb.UInt32(12345),
			},
		},
	}

	result, err := EvaluateExpression(prog, event, 0)
	require.NoError(t, err, "Failed to evaluate expression")

	// The result will be a wrapped protobuf value or native type
	// CEL may unwrap it automatically
	switch v := result.(type) {
	case *wrapperspb.UInt32Value:
		assert.Equal(t, uint32(12345), v.Value)
	case uint32:
		assert.Equal(t, uint32(12345), v)
	case uint64:
		assert.Equal(t, uint64(12345), v)
	case int64:
		assert.Equal(t, int64(12345), v)
	default:
		t.Fatalf("Unexpected result type: %T (value: %v)", result, result)
	}
}

// Test that both forms work: workload.* and event.workload.*
func TestEventPrefixOptional(t *testing.T) {
	env, err := createCELEnvironment()
	require.NoError(t, err, "Failed to create CEL environment")

	// Both forms work: event.workload.container.id
	prog, err := CompileExpression(env, `event.workload.container.id`)
	require.NoError(t, err, "Failed to compile expression")

	event := &v1beta1.Event{
		Name: "test_event",
		Workload: &v1beta1.Workload{
			Container: &v1beta1.Container{
				Id: "test-container",
			},
		},
	}

	result, err := EvaluateExpression(prog, event, 0)
	require.NoError(t, err, "Failed to evaluate expression")
	assert.Equal(t, "test-container", result)
}

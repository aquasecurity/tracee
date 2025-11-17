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
	env, err := createCELEnvironment(nil)
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
	result, err := EvaluateExpression(prog, event, nil, 0)
	require.NoError(t, err, "Failed to evaluate expression")

	// Verify result
	assert.Equal(t, "/etc/shadow", result)
}

// Test hasData macro
func TestHasDataMacro(t *testing.T) {
	env, err := createCELEnvironment(nil)
	require.NoError(t, err, "Failed to create CEL environment")

	prog, err := CompileExpression(env, `hasData("pathname")`)
	require.NoError(t, err, "Failed to compile hasData macro expression")

	event := &v1beta1.Event{
		Name: "test_event",
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", "/etc/shadow"),
		},
	}

	result, err := EvaluateExpression(prog, event, nil, 0)
	require.NoError(t, err, "Failed to evaluate expression")
	assert.Equal(t, true, result)

	// Test with missing field
	prog2, err := CompileExpression(env, `hasData("missing_field")`)
	require.NoError(t, err, "Failed to compile hasData macro expression")

	result2, err := EvaluateExpression(prog2, event, nil, 0)
	require.NoError(t, err, "Failed to evaluate expression")
	assert.Equal(t, false, result2)
}

// Test getDataInt macro
func TestGetDataIntMacro(t *testing.T) {
	env, err := createCELEnvironment(nil)
	require.NoError(t, err, "Failed to create CEL environment")

	prog, err := CompileExpression(env, `getData("uid")`)
	require.NoError(t, err, "Failed to compile getData for int32")

	event := &v1beta1.Event{
		Name: "test_event",
		Data: []*v1beta1.EventValue{
			v1beta1.NewInt32Value("uid", 1000),
		},
	}

	result, err := EvaluateExpression(prog, event, nil, 0)
	require.NoError(t, err, "Failed to evaluate expression")
	assert.Equal(t, int64(1000), result) // CEL converts int32 to int64
}

// Test getDataUInt macro
func TestGetDataUIntMacro(t *testing.T) {
	env, err := createCELEnvironment(nil)
	require.NoError(t, err, "Failed to create CEL environment")

	prog, err := CompileExpression(env, `getData("pid")`)
	require.NoError(t, err, "Failed to compile getData for uint32")

	event := &v1beta1.Event{
		Name: "test_event",
		Data: []*v1beta1.EventValue{
			v1beta1.NewUInt32Value("pid", 12345),
		},
	}

	result, err := EvaluateExpression(prog, event, nil, 0)
	require.NoError(t, err, "Failed to evaluate expression")
	assert.Equal(t, uint64(12345), result) // CEL converts uint32 to uint64
}

// Test getData with numeric comparisons (dynamic typing in action)
func TestGetDataNumericComparison(t *testing.T) {
	env, err := createCELEnvironment(nil)
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

	result, err := EvaluateCondition(prog, event, nil, 0)
	require.NoError(t, err, "Failed to evaluate numeric condition")
	assert.True(t, result)
}

// Test that both unary and binary forms work (macro expands unary to binary)
func TestGetDataBothCallForms(t *testing.T) {
	env, err := createCELEnvironment(nil)
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

	result, err := EvaluateExpression(prog, event, nil, 0)
	require.NoError(t, err, "Failed to evaluate expression")
	assert.Equal(t, "/etc/shadow", result)
}

// Test macro in complex expressions
func TestGetDataMacroInExpression(t *testing.T) {
	env, err := createCELEnvironment(nil)
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

	result, err := EvaluateExpression(prog, event, nil, 0)
	require.NoError(t, err, "Failed to evaluate expression")
	assert.Equal(t, true, result)
}

// Test macro with conditions
func TestGetDataMacroInCondition(t *testing.T) {
	env, err := createCELEnvironment(nil)
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

	result, err := EvaluateCondition(prog, event, nil, 0)
	require.NoError(t, err, "Failed to evaluate condition")
	assert.True(t, result)
}

// Test top-level workload variable (no "event." prefix)
func TestWorkloadTopLevelVariable(t *testing.T) {
	env, err := createCELEnvironment(nil)
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

	result, err := EvaluateExpression(prog, event, nil, 0)
	require.NoError(t, err, "Failed to evaluate expression")
	assert.Equal(t, "test-container-123", result)
}

// Test workload condition
func TestWorkloadInCondition(t *testing.T) {
	env, err := createCELEnvironment(nil)
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

	result, err := EvaluateCondition(prog, event, nil, 0)
	require.NoError(t, err, "Failed to evaluate condition")
	assert.True(t, result)
}

// Test combined: simplified getData + top-level workload
func TestCombinedSimplifiedSyntax(t *testing.T) {
	env, err := createCELEnvironment(nil)
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

	result, err := EvaluateCondition(prog, event, nil, 0)
	require.NoError(t, err, "Failed to evaluate condition")
	assert.True(t, result)
}

// Test workload.process.pid access
func TestWorkloadProcessAccess(t *testing.T) {
	env, err := createCELEnvironment(nil)
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

	result, err := EvaluateExpression(prog, event, nil, 0)
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
	env, err := createCELEnvironment(nil)
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

	result, err := EvaluateExpression(prog, event, nil, 0)
	require.NoError(t, err, "Failed to evaluate expression")
	assert.Equal(t, "test-container", result)
}

// Test that list variables are accessible in CEL expressions
func TestListVariables(t *testing.T) {
	// Create environment with shared lists
	lists := map[string][]string{
		"SHELL_BINARIES":  {"/bin/sh", "/bin/bash", "/usr/bin/zsh"},
		"SENSITIVE_PATHS": {"/etc/passwd", "/etc/shadow"},
	}

	env, err := createCELEnvironment(lists)
	require.NoError(t, err, "Failed to create CEL environment with lists")

	// Test 1: List variable exists and is accessible
	prog, err := CompileExpression(env, `SHELL_BINARIES`)
	require.NoError(t, err, "Failed to compile list variable expression")

	event := &v1beta1.Event{Name: "test_event"}

	result, err := EvaluateExpression(prog, event, lists, 0)
	require.NoError(t, err, "Failed to evaluate list variable")
	assert.Equal(t, []string{"/bin/sh", "/bin/bash", "/usr/bin/zsh"}, result)

	// Test 2: Multiple lists are accessible
	prog2, err := CompileExpression(env, `SENSITIVE_PATHS`)
	require.NoError(t, err, "Failed to compile second list variable expression")

	result2, err := EvaluateExpression(prog2, event, lists, 0)
	require.NoError(t, err, "Failed to evaluate second list variable")
	assert.Equal(t, []string{"/etc/passwd", "/etc/shadow"}, result2)
}

// Test 'in' operator with list variables
func TestListVariableInOperator(t *testing.T) {
	lists := map[string][]string{
		"SHELL_BINARIES": {"/bin/sh", "/bin/bash", "/usr/bin/zsh"},
	}

	env, err := createCELEnvironment(lists)
	require.NoError(t, err, "Failed to create CEL environment with lists")

	// Test condition: getData("pathname") in SHELL_BINARIES
	prog, err := CompileCondition(env, `getData("pathname") in SHELL_BINARIES`)
	require.NoError(t, err, "Failed to compile condition with list variable")

	// Test case 1: Value is in the list
	event1 := &v1beta1.Event{
		Name: "test_event",
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", "/bin/bash"),
		},
	}

	result1, err := EvaluateCondition(prog, event1, lists, 0)
	require.NoError(t, err, "Failed to evaluate condition")
	assert.True(t, result1, "Expected /bin/bash to be in SHELL_BINARIES")

	// Test case 2: Value is NOT in the list
	event2 := &v1beta1.Event{
		Name: "test_event",
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", "/usr/bin/cat"),
		},
	}

	result2, err := EvaluateCondition(prog, event2, lists, 0)
	require.NoError(t, err, "Failed to evaluate condition")
	assert.False(t, result2, "Expected /usr/bin/cat to NOT be in SHELL_BINARIES")
}

// Test that undefined list variables produce compilation error
func TestUndefinedListVariable(t *testing.T) {
	env, err := createCELEnvironment(nil)
	require.NoError(t, err, "Failed to create CEL environment")

	// Try to compile expression with undefined list variable
	_, err = CompileCondition(env, `getData("pathname") in UNDEFINED_LIST`)
	assert.Error(t, err, "Expected error for undefined list variable")
	assert.Contains(t, err.Error(), "undeclared reference to 'UNDEFINED_LIST'")
}

// Test list variables with complex expressions
func TestListVariableComplexExpressions(t *testing.T) {
	lists := map[string][]string{
		"SHELL_BINARIES":  {"/bin/sh", "/bin/bash"},
		"SENSITIVE_PATHS": {"/etc/passwd", "/etc/shadow"},
	}

	env, err := createCELEnvironment(lists)
	require.NoError(t, err, "Failed to create CEL environment with lists")

	// Test: getData("pathname") in SHELL_BINARIES || getData("pathname") in SENSITIVE_PATHS
	prog, err := CompileCondition(env, `getData("pathname") in SHELL_BINARIES || getData("pathname") in SENSITIVE_PATHS`)
	require.NoError(t, err, "Failed to compile complex expression")

	event := &v1beta1.Event{
		Name: "test_event",
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", "/etc/passwd"),
		},
	}

	result, err := EvaluateCondition(prog, event, lists, 0)
	require.NoError(t, err, "Failed to evaluate complex expression")
	assert.True(t, result, "Expected /etc/passwd to match complex condition")
}

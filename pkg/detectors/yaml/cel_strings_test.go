package yaml

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/api/v1beta1"
)

func TestSplitFunction(t *testing.T) {
	env, err := createCELEnvironment(nil, nil)
	require.NoError(t, err)

	// Test basic split
	prog, err := CompileExpression(env, `split("a,b,c", ",").size()`)
	require.NoError(t, err)
	result, err := EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, int64(3), result)

	// Test accessing split elements
	prog, err = CompileExpression(env, `split("a,b,c", ",")[0]`)
	require.NoError(t, err)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "a", result)

	// Test split with different delimiter
	prog, err = CompileExpression(env, `split("path/to/file", "/")[1]`)
	require.NoError(t, err)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "to", result)

	// Test split with empty string
	prog, err = CompileExpression(env, `split("", ",").size()`)
	require.NoError(t, err)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, int64(1), result)
}

func TestJoinFunction(t *testing.T) {
	env, err := createCELEnvironment(nil, nil)
	require.NoError(t, err)

	// Test basic join
	prog, err := CompileExpression(env, `join(["a", "b", "c"], ",")`)
	require.NoError(t, err)
	result, err := EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "a,b,c", result)

	// Test join with different delimiter
	prog, err = CompileExpression(env, `join(["path", "to", "file"], "/")`)
	require.NoError(t, err)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "path/to/file", result)

	// Test join with empty list
	prog, err = CompileExpression(env, `join([], ",")`)
	require.NoError(t, err)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "", result)

	// Test join with single element
	prog, err = CompileExpression(env, `join(["single"], "-")`)
	require.NoError(t, err)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "single", result)
}

func TestTrimFunction(t *testing.T) {
	env, err := createCELEnvironment(nil, nil)
	require.NoError(t, err)

	// Test trim with leading/trailing spaces
	prog, err := CompileExpression(env, `trim("  hello world  ")`)
	require.NoError(t, err)
	result, err := EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "hello world", result)

	// Test trim with tabs and newlines
	prog, err = CompileExpression(env, `trim("\t\nhello\n\t")`)
	require.NoError(t, err)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "hello", result)

	// Test trim with no whitespace
	prog, err = CompileExpression(env, `trim("hello")`)
	require.NoError(t, err)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "hello", result)

	// Test trim with empty string
	prog, err = CompileExpression(env, `trim("")`)
	require.NoError(t, err)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "", result)
}

func TestReplaceFunction(t *testing.T) {
	env, err := createCELEnvironment(nil, nil)
	require.NoError(t, err)

	// Test basic replace
	prog, err := CompileExpression(env, `replace("hello world", "world", "universe")`)
	require.NoError(t, err)
	result, err := EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "hello universe", result)

	// Test replace with multiple occurrences
	prog, err = CompileExpression(env, `replace("foo bar foo", "foo", "baz")`)
	require.NoError(t, err)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "baz bar baz", result)

	// Test replace with empty old string (replaces between every character)
	prog, err = CompileExpression(env, `replace("hello", "", "x")`)
	require.NoError(t, err)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "xhxexlxlxox", result) // Go's ReplaceAll behavior with empty string

	// Test replace with no match
	prog, err = CompileExpression(env, `replace("hello", "xyz", "abc")`)
	require.NoError(t, err)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "hello", result)
}

func TestUpperFunction(t *testing.T) {
	env, err := createCELEnvironment(nil, nil)
	require.NoError(t, err)

	// Test basic uppercase
	prog, err := CompileExpression(env, `upper("hello")`)
	require.NoError(t, err)
	result, err := EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "HELLO", result)

	// Test with mixed case
	prog, err = CompileExpression(env, `upper("HeLLo WoRLd")`)
	require.NoError(t, err)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "HELLO WORLD", result)

	// Test with already uppercase
	prog, err = CompileExpression(env, `upper("HELLO")`)
	require.NoError(t, err)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "HELLO", result)

	// Test with empty string
	prog, err = CompileExpression(env, `upper("")`)
	require.NoError(t, err)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "", result)
}

func TestLowerFunction(t *testing.T) {
	env, err := createCELEnvironment(nil, nil)
	require.NoError(t, err)

	// Test basic lowercase
	prog, err := CompileExpression(env, `lower("HELLO")`)
	require.NoError(t, err)
	result, err := EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "hello", result)

	// Test with mixed case
	prog, err = CompileExpression(env, `lower("HeLLo WoRLd")`)
	require.NoError(t, err)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "hello world", result)

	// Test with already lowercase
	prog, err = CompileExpression(env, `lower("hello")`)
	require.NoError(t, err)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "hello", result)

	// Test with empty string
	prog, err = CompileExpression(env, `lower("")`)
	require.NoError(t, err)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "", result)
}

func TestBasenameFunction(t *testing.T) {
	env, err := createCELEnvironment(nil, nil)
	require.NoError(t, err)

	// Test basic basename
	prog, err := CompileExpression(env, `basename("/path/to/file.txt")`)
	require.NoError(t, err)
	result, err := EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "file.txt", result)

	// Test with just filename
	prog, err = CompileExpression(env, `basename("file.txt")`)
	require.NoError(t, err)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "file.txt", result)

	// Test with directory ending in /
	prog, err = CompileExpression(env, `basename("/path/to/")`)
	require.NoError(t, err)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "to", result)

	// Test with root
	prog, err = CompileExpression(env, `basename("/")`)
	require.NoError(t, err)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "/", result)
}

func TestDirnameFunction(t *testing.T) {
	env, err := createCELEnvironment(nil, nil)
	require.NoError(t, err)

	// Test basic dirname
	prog, err := CompileExpression(env, `dirname("/path/to/file.txt")`)
	require.NoError(t, err)
	result, err := EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "/path/to", result)

	// Test with just filename (returns ".")
	prog, err = CompileExpression(env, `dirname("file.txt")`)
	require.NoError(t, err)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, ".", result)

	// Test with root directory
	prog, err = CompileExpression(env, `dirname("/file.txt")`)
	require.NoError(t, err)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "/", result)

	// Test with root
	prog, err = CompileExpression(env, `dirname("/")`)
	require.NoError(t, err)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "/", result)
}

func TestStringFunctionsInConditions(t *testing.T) {
	env, err := createCELEnvironment(nil, nil)
	require.NoError(t, err)

	// Test split and join in condition
	prog, err := CompileCondition(env, `join(split("a,b,c", ","), "-") == "a-b-c"`)
	require.NoError(t, err)
	result, err := EvaluateCondition(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.True(t, result)

	// Test basename in condition
	prog, err = CompileCondition(env, `basename("/path/to/file.txt") == "file.txt"`)
	require.NoError(t, err)
	result, err = EvaluateCondition(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.True(t, result)

	// Test upper and lower
	prog, err = CompileCondition(env, `upper("hello") == "HELLO" && lower("WORLD") == "world"`)
	require.NoError(t, err)
	result, err = EvaluateCondition(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.True(t, result)

	// Test replace
	prog, err = CompileCondition(env, `replace("foo bar", "bar", "baz") == "foo baz"`)
	require.NoError(t, err)
	result, err = EvaluateCondition(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.True(t, result)
}

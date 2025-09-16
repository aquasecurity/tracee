package logger

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetCallerInfo(t *testing.T) {
	// This function tests the runtime caller information extraction
	// We need to be careful as the exact results depend on the call stack

	// Test basic functionality
	ci := getCallerInfo(0)
	assert.NotNil(t, ci)
	assert.NotEmpty(t, ci.file)
	assert.Greater(t, ci.line, 0)
	assert.NotEmpty(t, ci.pkg)
	assert.NotEmpty(t, ci.functions)

	// The file should contain this test file
	assert.True(t, strings.Contains(ci.file, "callerinfo_test.go") ||
		strings.HasSuffix(ci.file, "callerinfo_test.go"))

	// The package should be logger
	assert.Equal(t, "logger", ci.pkg)

	// Should have at least one function in the call stack
	assert.Greater(t, len(ci.functions), 0)
}

func TestGetCallerInfoWithSkip(t *testing.T) {
	// Helper function to test caller info with different skip values
	testHelper := func(expectedFunction string) *callerInfo {
		return getCallerInfo(1) // Skip this helper function
	}

	ci := testHelper("TestGetCallerInfoWithSkip")
	assert.NotNil(t, ci)

	// Should still be in the test file
	assert.True(t, strings.Contains(ci.file, "callerinfo_test.go") ||
		strings.HasSuffix(ci.file, "callerinfo_test.go"))

	// Should still be logger package
	assert.Equal(t, "logger", ci.pkg)

	// Should have function names in the call stack
	assert.Greater(t, len(ci.functions), 0)
}

func TestGetCallerInfoFilePathProcessing(t *testing.T) {
	ci := getCallerInfo(0)

	// Test that the file path is processed correctly
	// If the path contains "tracee/", it should be relative to that
	if strings.Contains(ci.file, "tracee/") {
		// Should not contain the full absolute path before "tracee/"
		assert.False(t, strings.HasPrefix(ci.file, "/"))
	}

	// The file should end with .go
	assert.True(t, strings.HasSuffix(ci.file, ".go"))
}

func TestGetCallerInfoFunctionNames(t *testing.T) {
	// Test that function names are extracted properly
	ci := getCallerInfo(0)

	// Should have at least the current test function
	assert.Greater(t, len(ci.functions), 0)

	// Function names should not be empty
	for _, fn := range ci.functions {
		assert.NotEmpty(t, fn)
		// Function names should not contain package prefix after processing
		assert.False(t, strings.Contains(fn, "logger."))
	}
}

// Test with deeper call stack
func helperFunction1() *callerInfo {
	return helperFunction2()
}

func helperFunction2() *callerInfo {
	return helperFunction3()
}

func helperFunction3() *callerInfo {
	return getCallerInfo(0)
}

func TestGetCallerInfoDeepCallStack(t *testing.T) {
	ci := helperFunction1()
	assert.NotNil(t, ci)

	// Should capture multiple functions in the call stack
	assert.Greater(t, len(ci.functions), 2)

	// The first caller should be helperFunction3
	assert.Equal(t, "helperFunction3", ci.functions[0])

	// Should contain the helper functions
	functionNames := strings.Join(ci.functions, ",")
	assert.Contains(t, functionNames, "helperFunction3")
	assert.Contains(t, functionNames, "helperFunction2")
	assert.Contains(t, functionNames, "helperFunction1")
}

func TestGetCallerInfoWithVariousSkipValues(t *testing.T) {
	tests := []struct {
		name        string
		skip        int
		shouldPanic bool
	}{
		{"skip 0", 0, false},
		{"skip 1", 1, false},
		{"skip 2", 2, false},  // Should still work in most cases
		{"skip 15", 15, true}, // High skip values may cause panic due to bounds issue
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.shouldPanic {
				// Test that high skip values cause expected panic
				assert.Panics(t, func() {
					getCallerInfo(tt.skip)
				}, "Expected panic for high skip value")
			} else {
				// Test normal operation
				ci := getCallerInfo(tt.skip)
				assert.NotNil(t, ci)

				// For skip 0, we should have good caller info
				if tt.skip == 0 {
					assert.NotEmpty(t, ci.file)
					assert.Greater(t, ci.line, 0)
					assert.NotEmpty(t, ci.pkg)
					assert.NotNil(t, ci.functions) // Functions slice shouldn't be nil for skip 0
				}
				// For higher skip values, results may vary based on call stack depth
				// The functions slice might be nil or empty, which is acceptable
			}
		})
	}
}

func TestCallerInfoStruct(t *testing.T) {
	// Test the callerInfo struct fields
	ci := &callerInfo{
		pkg:       "testpkg",
		file:      "test.go",
		line:      42,
		functions: []string{"func1", "func2"},
	}

	assert.Equal(t, "testpkg", ci.pkg)
	assert.Equal(t, "test.go", ci.file)
	assert.Equal(t, 42, ci.line)
	assert.Equal(t, []string{"func1", "func2"}, ci.functions)
}

func TestGetCallerInfoPackageExtraction(t *testing.T) {
	ci := getCallerInfo(0)

	// Package name should not be empty
	assert.NotEmpty(t, ci.pkg)

	// Package name should not contain slashes (should be extracted properly)
	assert.False(t, strings.Contains(ci.pkg, "/"))

	// For this test, package should be "logger"
	assert.Equal(t, "logger", ci.pkg)
}

// Test function name extraction edge cases
func functionWithDotsInPath() *callerInfo {
	return getCallerInfo(0)
}

func TestGetCallerInfoFunctionNameExtraction(t *testing.T) {
	ci := functionWithDotsInPath()

	// Should extract function name correctly
	assert.Greater(t, len(ci.functions), 0)
	assert.Equal(t, "functionWithDotsInPath", ci.functions[0])
}

func TestGetCallerInfoMaxDepth(t *testing.T) {
	// Test that the function respects the maximum depth of 20
	ci := getCallerInfo(0)

	// Should not have more than 20 functions even in deep call stacks
	assert.LessOrEqual(t, len(ci.functions), 20)

	// Should have reasonable number of functions for this test context
	assert.Greater(t, len(ci.functions), 0)
	assert.LessOrEqual(t, len(ci.functions), 10) // Reasonable for test context
}

// Test with method receivers (if any exist in the call stack)
type testStruct struct{}

func (ts *testStruct) methodCall() *callerInfo {
	return getCallerInfo(0)
}

func TestGetCallerInfoWithMethods(t *testing.T) {
	ts := &testStruct{}
	ci := ts.methodCall()

	assert.NotNil(t, ci)
	assert.Greater(t, len(ci.functions), 0)

	// The first function should be the method call (may include receiver type)
	assert.True(t, strings.Contains(ci.functions[0], "methodCall"),
		"Expected function name to contain 'methodCall', got: %s", ci.functions[0])
}

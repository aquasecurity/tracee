package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/tracee/types/detect"
	"github.com/open-policy-agent/opa/compile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// FIXME Don't relay on Git project structure to run unit tests.
	exampleRulesDir = "../../signatures/rego"
)

func Test_getSignatures(t *testing.T) {
	sigs, err := getSignatures(compile.TargetRego, false, exampleRulesDir, []string{"TRC-2"}, false)
	require.NoError(t, err)
	require.Equal(t, 1, len(sigs))

	gotMetadata, err := sigs[0].GetMetadata()
	require.NoError(t, err)
	assert.Equal(t, detect.SignatureMetadata{
		ID:          "TRC-2",
		Version:     "0.1.0",
		Name:        "Anti-Debugging",
		Description: "Process uses anti-debugging technique to block debugger",
		Tags:        []string{"linux", "container"},
		Properties: map[string]interface{}{
			"MITRE ATT&CK": "Defense Evasion: Execution Guardrails",
			"Severity":     json.Number("3"),
		},
	}, gotMetadata)
}

func Test_isHelper(t *testing.T) {
	testCases := []struct {
		input    string
		expected bool
	}{
		{"helpers.rego", true},
		{"test_helpers.rego", true},
		{"new_helpers.rego", true},
		{"test.rego", false},
		{"new.rego", false},
		{"test_new.rego", false},
		{"helpers.go", false},
		{"test_helpers.go", false},
		{"aaa.go", false},
		{"helpers", false},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			actual := isHelper(tc.input)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func Test_findRegoSigs(t *testing.T) {
	// create test signature directory, clean it up after the test
	testRoot, err := ioutil.TempDir(os.TempDir(), "")
	require.NoError(t, err)
	defer os.RemoveAll(testRoot)

	// create directory to test nested rule directories
	testDir := filepath.Join(testRoot, "test")
	err = os.Mkdir(testDir, 0777)
	require.NoError(t, err)

	// copy example go signature to test dir and it's child dir
	err = copyExampleSig("anti_debugging_ptraceme.rego", testRoot)
	require.NoError(t, err)
	err = copyExampleSig("anti_debugging_ptraceme.rego", testDir)
	require.NoError(t, err)

	// find rego signatures
	sigs, err := findRegoSigs(compile.TargetRego, false, testRoot, false)
	require.NoError(t, err)

	assert.Equal(t, len(sigs), 2)
	for _, sig := range sigs {
		gotMetadata, err := sig.GetMetadata()
		require.NoError(t, err)
		assert.Equal(t, detect.SignatureMetadata{
			ID:          "TRC-2",
			Version:     "0.1.0",
			Name:        "Anti-Debugging",
			Description: "Process uses anti-debugging technique to block debugger",
			Tags:        []string{"linux", "container"},
			Properties: map[string]interface{}{
				"MITRE ATT&CK": "Defense Evasion: Execution Guardrails",
				"Severity":     json.Number("3"),
			},
		}, gotMetadata)
	}
}

func copyExampleSig(exampleName, destDir string) error {
	var exampleDir string
	extension := filepath.Ext(exampleName)
	if extension == ".rego" {
		exampleDir = fmt.Sprint(exampleRulesDir + "/%s")
	} else {
		return errors.New("unsupported signature type")
	}

	// copy example signature
	exampleFile := fmt.Sprintf(exampleDir, exampleName)
	_, err := os.Stat(exampleFile)
	if err != nil {
		return err
	}
	file, err := ioutil.ReadFile(exampleFile)
	if err != nil {
		return err
	}

	// write example sig to directory
	testSig := "test" + extension
	err = ioutil.WriteFile(filepath.Join(destDir, testSig), file, 0777)
	if err != nil {
		return err
	}
	return nil
}

func Test_isRegoFile(t *testing.T) {
	testCases := []struct {
		input    string
		expected bool
	}{
		{"helpers.rego", true},
		{"test_helpers.rego", true},
		{"helpers.go", false},
		{"builtin.so", false},
		{"helpers", false},
		{"helpers.txt", false},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			actual := isHelper(tc.input)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

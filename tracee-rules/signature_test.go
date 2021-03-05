package main

import (
	"encoding/json"
	"testing"

	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_getSignatures(t *testing.T) {
	sigs, err := getSignatures("signatures/rego", []string{"TRC-2"})
	require.NoError(t, err)
	require.Equal(t, 1, len(sigs))

	gotMetadata, err := sigs[0].GetMetadata()
	assert.Equal(t, types.SignatureMetadata{
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

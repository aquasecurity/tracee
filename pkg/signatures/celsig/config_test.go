package celsig_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/signatures/celsig"
	"github.com/aquasecurity/tracee/types/detect"
)

func TestNewConfigFromFile(t *testing.T) {
	config, err := celsig.NewConfigFromFile("testdata/rules/anti_debugging_ptraceme.yml")
	require.NoError(t, err)
	assert.Equal(t, celsig.SignaturesConfig{
		Kind:       celsig.KindSignaturesConfig,
		APIVersion: celsig.APIVersionV1Alpha1,
		Signatures: []celsig.SignatureConfig{
			{
				Metadata: detect.SignatureMetadata{
					ID:      "CEL-2",
					Version: "0.1.0",
					Name:    "Anti-Debugging",
					Tags: []string{
						"linux",
						"containers",
					},
					Properties: map[string]interface{}{
						"Severity":     3,
						"MITRE ATT&CK": "Defense Evasion: Execution Guardrails",
					},
				},
				EventSelectors: []detect.SignatureEventSelector{
					{
						Source: "tracee",
						Name:   "ptrace",
					},
				},
				Expression: `input.eventName == 'ptrace' && input.stringArg('request') == 'PTRACE_TRACEME'`,
			},
		},
	}, config)
}

package regosig_test

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/open-policy-agent/opa/compile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/signatures/regosig"
	"github.com/aquasecurity/tracee/signatures/signaturestest"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestAio_GetMetadata(t *testing.T) {
	t.Parallel()

	sig, err := regosig.NewAIO(map[string]string{
		"test_boolean.rego": testRegoCodeBoolean,
		"test_object.rego":  testRegoCodeObject,
	})
	require.NoError(t, err)

	metadata, err := sig.GetMetadata()
	require.NoError(t, err)
	assert.Equal(t, detect.SignatureMetadata{
		ID:      "TRC-AIO (TRC-BOOL,TRC-OBJECT)",
		Version: "1.0.0",
		Name:    "AIO",
	}, metadata)
}

func TestAio_GetSelectedEvents(t *testing.T) {
	t.Parallel()

	sig, err := regosig.NewAIO(map[string]string{
		"test_boolean.rego": testRegoCodeBoolean,
		"test_object.rego":  testRegoCodeObject,
	})
	require.NoError(t, err)
	events, err := sig.GetSelectedEvents()
	require.NoError(t, err)

	eventsSet := make(map[detect.SignatureEventSelector]bool)
	for _, event := range events {
		if _, value := eventsSet[event]; !value {
			eventsSet[event] = true
		}
	}

	assert.Equal(t, map[detect.SignatureEventSelector]bool{
		{
			Source: "tracee",
			Name:   "ptrace",
		}: true,
		{
			Source: "tracee",
			Name:   "execve",
		}: true,
	}, eventsSet)
}

func TestAio_OnEvent(t *testing.T) {
	t.Parallel()

	options := []struct {
		target  string
		partial bool
	}{
		{
			target:  compile.TargetRego,
			partial: false,
		},
		{
			target:  compile.TargetRego,
			partial: true,
		},
	}

	for _, tc := range options {
		tc := tc

		t.Run(fmt.Sprintf("target=%s,partial=%t", tc.target, tc.partial), func(t *testing.T) {
			t.Parallel()

			AioOnEventSpec(t, tc.target, tc.partial)
		})
	}

}

// AioOnEventSpec describes the behavior of aio.OnEvent.
func AioOnEventSpec(t *testing.T, target string, partial bool) {
	testCases := []struct {
		name    string
		modules map[string]string
		event   trace.Event
		// findings are grouped by signature identifier for comparison
		findings  map[string]*detect.Finding
		wantError string
	}{
		{
			name: "Should return finding when single rule matches",
			modules: map[string]string{
				"test_boolean.rego": testRegoCodeBoolean,
				"test_object.rego":  testRegoCodeObject,
			},
			event: trace.Event{
				Args: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "doesn't matter",
						},
						Value: "ends with yo",
					},
				},
			},
			findings: map[string]*detect.Finding{
				"TRC-BOOL": {
					Data: nil,
					Event: trace.Event{
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "doesn't matter",
								},
								Value: "ends with yo",
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-BOOL",
						Version:     "0.1.0",
						Name:        "test name",
						Description: "test description",
						Tags: []string{
							"tag1",
							"tag2",
						},
						Properties: map[string]interface{}{
							"p1": "test",
							"p2": json.Number("1"),
							"p3": true,
						},
					},
				},
			},
		},
		{
			name: "Should return multiple findings when multiple rules match",
			modules: map[string]string{
				"test_boolean.rego": testRegoCodeBoolean,
				"test_object.rego":  testRegoCodeObject,
			},
			event: trace.Event{
				Args: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "doesn't matter",
						},
						Value: "ends with yo",
					},
					{
						ArgMeta: trace.ArgMeta{
							Name: "doesn't matter",
						},
						Value: 1337,
					},
				},
			},
			findings: map[string]*detect.Finding{
				"TRC-OBJECT": {
					Data: map[string]interface{}{
						"p1": "test",
						"p2": json.Number("1"),
						"p3": true,
					},
					Event: trace.Event{
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "doesn't matter",
								},
								Value: "ends with yo",
							},
							{
								ArgMeta: trace.ArgMeta{
									Name: "doesn't matter",
								},
								Value: 1337,
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-OBJECT",
						Version:     "0.3.0",
						Name:        "test name",
						Description: "test description",
						Tags: []string{
							"tag1",
							"tag2",
						},
						Properties: map[string]interface{}{
							"p1": "test",
							"p2": json.Number("1"),
							"p3": true,
						},
					},
				},
				"TRC-BOOL": {
					Data: nil,
					Event: trace.Event{
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "doesn't matter",
								},
								Value: "ends with yo",
							},
							{
								ArgMeta: trace.ArgMeta{
									Name: "doesn't matter",
								},
								Value: 1337,
							},
						},
					}.ToProtocol(),
					SigMetadata: detect.SignatureMetadata{
						ID:          "TRC-BOOL",
						Version:     "0.1.0",
						Name:        "test name",
						Description: "test description",
						Tags: []string{
							"tag1",
							"tag2",
						},
						Properties: map[string]interface{}{
							"p1": "test",
							"p2": json.Number("1"),
							"p3": true,
						},
					},
				},
			},
		},
		{
			name: "Should return error when invalid value received",
			modules: map[string]string{
				"test_invalid.rego": testRegoCodeInvalidObject,
			},
			event: trace.Event{
				Args: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "doesn't matter",
						},
						Value: "ends with invalid",
					},
				},
			},
			wantError: "unrecognized value: string",
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sig, err := regosig.NewAIO(tc.modules,
				regosig.OPATarget(target),
				regosig.OPAPartial(partial),
			)
			require.NoError(t, err)

			holder := &signaturestest.FindingsHolder{}
			err = sig.Init(detect.SignatureContext{Callback: holder.OnFinding})
			require.NoError(t, err)

			err = sig.OnEvent(tc.event.ToProtocol())
			if tc.wantError != "" {
				require.EqualError(t, err, tc.wantError, tc.name)
			} else {
				require.NoError(t, err, tc.name)
				assert.Equal(t, tc.findings, holder.GroupBySigID())
			}
		})
	}
}

func TestAio_OnSignal(t *testing.T) {
	t.Parallel()

	sig, err := regosig.NewAIO(map[string]string{})
	require.NoError(t, err)
	err = sig.OnSignal(os.Kill)
	assert.EqualError(t, err, "unsupported operation")
}

package regosig_test

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	tracee "github.com/aquasecurity/tracee/tracee-ebpf/external"
	"github.com/aquasecurity/tracee/tracee-rules/engine"
	"github.com/aquasecurity/tracee/tracee-rules/signatures/rego/regosig"
	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/open-policy-agent/opa/compile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testRegoCodeBoolean = `package tracee.TRC_BOOL

__rego_metadoc__ := {
	"id": "TRC-BOOL",
	"version": "0.1.0",
	"name": "test name",
	"description": "test description",
	"tags": [ "tag1", "tag2" ],
	"properties": {
		"p1": "test",
		"p2": 1,
		"p3": true
	}
}

tracee_selected_events[eventSelector] {
	eventSelector := {
		"source": "tracee",
		"name": "execve"
	}
}

tracee_match {
	endswith(input.args[0].value, "yo")
}
`
	testRegoCodeObject = `package tracee.TRC_OBJECT

__rego_metadoc__ := {
	"id": "TRC-OBJECT",
	"version": "0.3.0",
	"name": "test name",
	"description": "test description",
	"tags": [ "tag1", "tag2" ],
	"properties": {
		"p1": "test",
		"p2": 1,
		"p3": true
	}
}

tracee_selected_events[eventSelector] {
	eventSelector := {
		"source": "tracee",
		"name": "execve"
	}
}

tracee_match = res {
	endswith(input.args[0].value, "yo")
	input.args[1].value == 1337
	res := {
		"p1": "test",
		"p2": 1,
		"p3": true
	}
}
`
)

// findingHolder is a utility struct that defines types.SignatureHandler callback method
// and holds the types.Finding value received as the callback's argument.
type findingHolder struct {
	value *types.Finding
}

func (h *findingHolder) OnFinding(f types.Finding) {
	h.value = &f
}

func TestRegoSignature_GetMetadata(t *testing.T) {
	sig, err := regosig.NewRegoSignature(compile.TargetRego, false, testRegoCodeBoolean)
	require.NoError(t, err)

	metadata, err := sig.GetMetadata()
	require.NoError(t, err)
	assert.Equal(t, types.SignatureMetadata{
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
	}, metadata)
}

func TestRegoSignature_GetSelectedEvents(t *testing.T) {
	sig, err := regosig.NewRegoSignature(compile.TargetRego, false, testRegoCodeBoolean)
	require.NoError(t, err)
	events, err := sig.GetSelectedEvents()
	require.NoError(t, err)
	assert.Equal(t, []types.SignatureEventSelector{
		{
			Source: "tracee",
			Name:   "execve",
		},
	}, events)
}

func TestRegoSignature_OnEvent(t *testing.T) {
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
		{
			target:  compile.TargetWasm,
			partial: false,
		},
		{
			target:  compile.TargetWasm,
			partial: true,
		},
	}

	for _, tc := range options {
		t.Run(fmt.Sprintf("target=%s,partial=%t", tc.target, tc.partial), func(t *testing.T) {
			OnEventSpec(t, tc.target, tc.partial)
		})
	}

}

// OnEventSpec describes the behavior of RegoSignature.OnEvent.
func OnEventSpec(t *testing.T, target string, partial bool) {
	testCases := []struct {
		name       string
		regoCode   string
		event      tracee.Event
		parseEvent bool

		finding *types.Finding
		error   string
	}{
		{
			name:     "Should trigger finding when tracee_match rule returns boolean and event matches",
			regoCode: testRegoCodeBoolean,
			event: tracee.Event{
				Args: []tracee.Argument{
					{
						ArgMeta: tracee.ArgMeta{
							Name: "doesn't matter",
						},
						Value: "ends with yo",
					},
				},
			},
			finding: &types.Finding{
				Data: nil,
				Context: tracee.Event{
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "doesn't matter",
							},
							Value: "ends with yo",
						},
					},
				},
				SigMetadata: types.SignatureMetadata{
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
		{
			name:     "Should trigger finding when tracee_match rule returns boolean and parsed event matches",
			regoCode: testRegoCodeBoolean,
			event: tracee.Event{
				Args: []tracee.Argument{
					{
						ArgMeta: tracee.ArgMeta{
							Name: "doesn't matter",
						},
						Value: "ends with yo",
					},
				},
			},
			parseEvent: true,
			finding: &types.Finding{
				Data: nil,
				Context: tracee.Event{
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "doesn't matter",
							},
							Value: "ends with yo",
						},
					},
				},
				SigMetadata: types.SignatureMetadata{
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
		{
			name:     "Shouldn't trigger finding when tracee_match rule returns boolean but event doesn't match",
			regoCode: testRegoCodeBoolean,
			event: tracee.Event{
				Args: []tracee.Argument{
					{
						ArgMeta: tracee.ArgMeta{
							Name: "doesn't matter",
						},
						Value: "doesn't end with yo!",
					},
				},
			},
			finding: nil,
		},
		{
			name:     "Should trigger finding when tracee_match rule returns object and event matches",
			regoCode: testRegoCodeObject,
			event: tracee.Event{
				Args: []tracee.Argument{
					{
						ArgMeta: tracee.ArgMeta{
							Name: "doesn't matter",
						},
						Value: "ends with yo",
					},
					{
						ArgMeta: tracee.ArgMeta{
							Name: "doesn't matter",
						},
						Value: 1337,
					},
				},
			},
			finding: &types.Finding{
				Data: map[string]interface{}{
					"p1": "test",
					"p2": json.Number("1"),
					"p3": true,
				},
				Context: tracee.Event{
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "doesn't matter",
							},
							Value: "ends with yo",
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "doesn't matter",
							},
							Value: 1337,
						},
					},
				},
				SigMetadata: types.SignatureMetadata{
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
		},
		{
			name:     "Should trigger finding when tracee_match rule returns object and parsed event matches",
			regoCode: testRegoCodeObject,
			event: tracee.Event{
				Args: []tracee.Argument{
					{
						ArgMeta: tracee.ArgMeta{
							Name: "doesn't matter",
						},
						Value: "ends with yo",
					},
					{
						ArgMeta: tracee.ArgMeta{
							Name: "doesn't matter",
						},
						Value: 1337,
					},
				},
			},
			parseEvent: true,
			finding: &types.Finding{
				Data: map[string]interface{}{
					"p1": "test",
					"p2": json.Number("1"),
					"p3": true,
				},
				Context: tracee.Event{
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "doesn't matter",
							},
							Value: "ends with yo",
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "doesn't matter",
							},
							Value: 1337,
						},
					},
				},
				SigMetadata: types.SignatureMetadata{
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
		},
		{
			name:     "Shouldn't trigger finding when tracee_match rule returns object but event doesn't match",
			regoCode: testRegoCodeObject,
			event: tracee.Event{
				Args: []tracee.Argument{
					{
						ArgMeta: tracee.ArgMeta{
							Name: "doesn't matter",
						},
						Value: "yo is not at end",
					},
				},
			},
			finding: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sig, err := regosig.NewRegoSignature(target, partial, tc.regoCode)
			require.NoError(t, err)

			holder := &findingHolder{}
			err = sig.Init(holder.OnFinding)
			require.NoError(t, err)

			var event interface{}

			if tc.parseEvent {
				event, err = engine.ToParsedEvent(tc.event)
				require.NoError(t, err)
			} else {
				event = tc.event
			}

			err = sig.OnEvent(event)
			if tc.error != "" {
				assert.EqualError(t, err, tc.error)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.finding, holder.value)
			}
		})
	}

	t.Run("Should return error when event has unrecognized type", func(t *testing.T) {
		sig, err := regosig.NewRegoSignature(target, partial, testRegoCodeBoolean)
		require.NoError(t, err)

		err = sig.OnEvent("UNRECOGNIZED")
		assert.EqualError(t, err, "unrecognized event type: string")
	})
}

func TestRegoSignature_OnSignal(t *testing.T) {
	sig, err := regosig.NewRegoSignature(compile.TargetRego, false, testRegoCodeBoolean)
	require.NoError(t, err)
	err = sig.OnSignal(os.Kill)
	assert.EqualError(t, err, "function OnSignal is not implemented")
}

func Test_generateRegoMap(t *testing.T) {
	type args struct {
		regoCodes []string
	}
	tests := []struct {
		name        string
		args        args
		wantPkgName string
		wantRegoMap map[string]string
		wantErr     string
	}{
		{
			name: "happy path, single rego policy",
			args: args{regoCodes: []string{`package FOO_1

__rego_metadoc__ := {
	"id": "FOO-1",
	"name": "example1"
}

tracee_selected_events[eventSelector] {
	eventSelector := {
		"source": "tracee",
		#"name": "execve"
	}
}

tracee_match {
	endswith(input.args[0].value, "foo")
}`},
			},
			wantPkgName: "FOO_1",
			wantRegoMap: map[string]string{
				"FOO_1": `package FOO_1

__rego_metadoc__ := {
	"id": "FOO-1",
	"name": "example1"
}

tracee_selected_events[eventSelector] {
	eventSelector := {
		"source": "tracee",
		#"name": "execve"
	}
}

tracee_match {
	endswith(input.args[0].value, "foo")
}`,
			},
		},
		{
			name: "happy path, rego policy with helpers.rego",
			args: args{regoCodes: []string{`package FOO_1

__rego_metadoc__ := {
	"id": "FOO-1",
	"name": "example1"
}

tracee_selected_events[eventSelector] {
	eventSelector := {
		"source": "tracee",
		#"name": "execve"
	}
}

tracee_match {
	endswith(input.args[0].value, "foo")
}`, `package tracee.helpers

get_tracee_argument(arg_name) = res {
    arg := input.args[_]
    arg.name == arg_name
    res := arg.value
}`},
			},
			wantPkgName: "FOO_1",
			wantRegoMap: map[string]string{
				"FOO_1": `package FOO_1

__rego_metadoc__ := {
	"id": "FOO-1",
	"name": "example1"
}

tracee_selected_events[eventSelector] {
	eventSelector := {
		"source": "tracee",
		#"name": "execve"
	}
}

tracee_match {
	endswith(input.args[0].value, "foo")
}`,
				"tracee.helpers": `package tracee.helpers

get_tracee_argument(arg_name) = res {
    arg := input.args[_]
    arg.name == arg_name
    res := arg.value
}`,
			},
		},
		{
			name:    "sad path, invalid rego policy",
			args:    args{regoCodes: []string{`invalid policy`}},
			wantErr: "invalid rego code received",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPkgName, gotRegoMap, err := generateRegoMap(tt.args.regoCodes...)
			if tt.wantErr != "" {
				assert.Equal(t, tt.wantErr, err.Error(), tt.name)
			} else {
				require.NoError(t, err, tt.name)
				assert.Equal(t, tt.wantPkgName, gotPkgName, tt.name)
				assert.Equal(t, tt.wantRegoMap, gotRegoMap, tt.name)
			}
		})
	}
}

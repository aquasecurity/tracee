package regosig_test

import (
	"testing"

	"github.com/aquasecurity/tracee/tracee-rules/signatures/rego/regosig"

	tracee "github.com/aquasecurity/tracee/tracee-ebpf/external"

	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/open-policy-agent/opa/compile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testRegoCodes = []string{`package FOO_1

__rego_metadoc__ := {
	"id": "FOO-1",
	"name": "example1"
}

tracee_selected_events[eventSelector] {
	eventSelector := {
		"source": "tracee",
	}
}

tracee_match {
	endswith(input.args[0].value, "yo")
}`, `package FOO_2

__rego_metadoc__ := {
	"id": "FOO-2",
	"name": "example2"
}

tracee_selected_events[eventSelector] {
	eventSelector := {
		"source": "tracee",
	}
}

tracee_match = res {
	endswith(input.args[0].value, "yo")
	res := { "Severity": 1 }
}`}

func TestNewAIORegoSignature(t *testing.T) {
	type args struct {
		o         regosig.Options
		regoCodes []string
	}
	tests := []struct {
		name               string
		args               args
		wantMetadata       types.SignatureMetadata
		wantSelectedEvents []types.SignatureEventSelector
		wantErr            string
	}{
		{
			name: "happy path, partial eval off, rego target",
			args: args{
				o:         regosig.Options{PartialEval: false, Target: compile.TargetRego},
				regoCodes: testRegoCodes,
			},
			wantMetadata: types.SignatureMetadata{
				ID:          "TRC-AIO",
				Version:     "0.1.0",
				Name:        "All In One Rego Rule",
				Description: "This rule indexes all loaded Rego rules via one.",
			},
			wantSelectedEvents: []types.SignatureEventSelector{
				{Source: "tracee",
					Name:   "*",
					Origin: "",
				},
			},
		},
		// TODO: Add sad path test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := regosig.NewAIORegoSignature(tt.args.o, tt.args.regoCodes...)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr, tt.name)
			} else {
				require.NoError(t, err, tt.name)
				gotMetadata, err := got.GetMetadata("tracee_aio")
				require.NoError(t, err, tt.name)
				assert.Equal(t, tt.wantMetadata, gotMetadata, tt.name)

				gotSelectedEvents, err := got.GetSelectedEvents("tracee_aio")
				require.NoError(t, err, tt.name)
				assert.Equal(t, tt.wantSelectedEvents, gotSelectedEvents, tt.name)
			}
		})
	}
}

func TestAIORegoSignature_OnEvent(t *testing.T) {
	aio, err := regosig.NewAIORegoSignature(regosig.Options{
		PartialEval: false,
		Target:      compile.TargetRego,
	}, []string{testRegoCodeBoolean, testRegoCodeObject}...)
	require.NoError(t, err)

	holder := &findingHolder{}
	err = aio.Init(holder.OnFinding)
	require.NoError(t, err)

	inputEvent := tracee.Event{
		Args: []tracee.Argument{
			{
				ArgMeta: tracee.ArgMeta{
					Name: "doesn't matter",
				},
				Value: "ends with yo",
			},
		},
	}
	require.NoError(t, aio.OnEvent(inputEvent))
	assert.Equal(t, types.Finding{
		Data: map[string]interface{}{"TRC-BOOL": true},
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
		SigMetadata: types.SignatureMetadata{ID: "TRC-AIO", Version: "0.1.0", Name: "All In One Rego Rule", Description: "This rule indexes all loaded Rego rules via one."},
	}, *holder.value)
}

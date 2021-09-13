package regosig

import (
	"testing"

	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/open-policy-agent/opa/compile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAIORegoSignature(t *testing.T) {
	type args struct {
		o         Options
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
				o: Options{PartialEval: false, Target: compile.TargetRego},
				regoCodes: []string{`package FOO_1

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
	endswith(input.args[0].value, "yo")
}`, `package FOO_2

__rego_metadoc__ := {
	"id": "FOO-2",
	"name": "example2"
}

tracee_selected_events[eventSelector] {
	eventSelector := {
		"source": "tracee",
		#"name": "execve"
	}
}

tracee_match = res {
	endswith(input.args[0].value, "yo")
	res := { "Severity": 1 }
}`},
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
			got, err := NewAIORegoSignature(tt.args.o, tt.args.regoCodes...)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr, tt.name)
			} else {
				require.NoError(t, err, tt.name)
				gotMetadata, err := got.GetMetadata()
				require.NoError(t, err, tt.name)
				assert.Equal(t, tt.wantMetadata, gotMetadata, tt.name)

				gotSelectedEvents, err := got.GetSelectedEvents()
				require.NoError(t, err, tt.name)
				assert.Equal(t, tt.wantSelectedEvents, gotSelectedEvents, tt.name)
			}
		})
	}
}

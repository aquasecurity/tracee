package events

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/types/trace"
)

func TestNewDefinition(t *testing.T) {
	t.Parallel()

	expectedDefinition := Definition{
		name: "hooked_seq_ops2",
		dependencies: Dependencies{
			ids:          []ID{PrintNetSeqOps, DoInitModule},
			kSymbols:     []KSymbol{},
			probes:       []Probe{},
			tailCalls:    []TailCall{},
			capabilities: Capabilities{},
		},
		sets: []string{"signatures"},
	}

	eventDefinition := NewDefinition(
		0,
		Sys32Undefined,
		"hooked_seq_ops2",
		version,
		"",
		"",
		false,
		false,
		[]string{"signatures"},
		NewDependencies(
			[]ID{PrintNetSeqOps, DoInitModule},
			[]KSymbol{},
			[]Probe{},
			[]TailCall{},
			Capabilities{},
		),
		[]trace.ArgMeta{},
		nil,
	)

	assert.Equal(t, expectedDefinition.GetName(), eventDefinition.GetName())
	assert.Equal(t, expectedDefinition.GetDependencies(), eventDefinition.GetDependencies())
}

func TestAdd(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		evt  Definition
		err  string
	}{
		{
			name: "new definition",
			evt: Definition{
				id32Bit: ID(6000),
				name:    "new_event",
				dependencies: Dependencies{
					ids: []ID{
						PrintNetSeqOps,
						DoInitModule,
					},
				},
				sets: []string{"signatures"},
			},
		},
		{
			name: "definition id already exists",
			evt: Definition{
				id32Bit: ID(700),
				name:    "new_event",
				dependencies: Dependencies{
					ids: []ID{
						PrintNetSeqOps,
						DoInitModule,
					},
				},
				sets: []string{"signatures"},
			},
			err: "definition id already exists: 700",
		},
		{
			name: "definition name already exists",
			evt: Definition{
				id32Bit: ID(6001),
				name:    "net_packet",
				dependencies: Dependencies{
					ids: []ID{
						PrintNetSeqOps,
						DoInitModule,
					},
				},
				sets: []string{"signatures"},
			},
			err: "definition name already exists: net_packet",
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := Core.Add(test.evt.GetID32Bit(), test.evt)
			if err != nil {
				assert.ErrorContains(t, err, test.err)
				return
			}

			eventDefID, ok := Core.GetDefinitionIDByName(test.evt.GetName())
			assert.True(t, ok)

			eventDefinition := Core.GetDefinitionByID(eventDefID)
			assert.Equal(t, test.evt, eventDefinition)
		})
	}
}

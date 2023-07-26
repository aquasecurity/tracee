package events

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewEventDefinition(t *testing.T) {
	expected := EventDefinition{
		name: "hooked_seq_ops2",
		dependencies: Dependencies{
			Events: []ID{
				PrintNetSeqOps,
				DoInitModule,
			},
		},
		sets: []string{"signatures"},
	}

	e := NewEventDefinition("hooked_seq_ops2", []string{"signatures"}, []ID{PrintNetSeqOps, DoInitModule})

	assert.Equal(t, expected.GetName(), e.GetName())
	assert.Equal(t, expected.GetDependencies(), e.GetDependencies())
}

func TestAdd(t *testing.T) {
	tests := []struct {
		name string
		evt  EventDefinition
		err  string
	}{
		{
			name: "new event",
			evt: EventDefinition{
				id32Bit: ID(6000),
				name:    "new_event",
				dependencies: Dependencies{
					Events: []ID{
						PrintNetSeqOps,
						DoInitModule,
					},
				},
				sets: []string{"signatures"},
			},
		},
		{
			name: "event id already exist",
			evt: EventDefinition{
				id32Bit: ID(700),
				name:    "new_event",
				dependencies: Dependencies{
					Events: []ID{
						PrintNetSeqOps,
						DoInitModule,
					},
				},
				sets: []string{"signatures"},
			},
			err: "error event id already exist: 700",
		},
		{
			name: "event name already exist",
			evt: EventDefinition{
				id32Bit: ID(6001),
				name:    "net_packet",
				dependencies: Dependencies{
					Events: []ID{
						PrintNetSeqOps,
						DoInitModule,
					},
				},
				sets: []string{"signatures"},
			},
			err: "error event name already exist: net_packet",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := CoreEventDefinitionGroup.Add(test.evt.GetID32Bit(), test.evt)
			if err != nil {
				assert.ErrorContains(t, err, test.err)
				return
			}

			id, ok := CoreEventDefinitionGroup.GetID(test.evt.GetName())
			assert.True(t, ok)

			event := CoreEventDefinitionGroup.Get(id)
			assert.Equal(t, test.evt, event)
		})
	}
}

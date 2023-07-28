package events

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/types/trace"
)

func TestNewEventDefinition(t *testing.T) {
	expected := Event{
		name: "hooked_seq_ops2",
		dependencies: Dependencies{
			events:       []ID{PrintNetSeqOps, DoInitModule},
			kSymbols:     []KSymbol{},
			probes:       []Probe{},
			tailCalls:    []TailCall{},
			capabilities: Capabilities{},
		},
		sets: []string{"signatures"},
	}

	e := NewEvent(
		0,
		Sys32Undefined,
		"hooked_seq_ops2",
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
	)

	assert.Equal(t, expected.GetName(), e.GetName())
	assert.Equal(t, expected.GetDependencies(), e.GetDependencies())
}

func TestAdd(t *testing.T) {
	tests := []struct {
		name string
		evt  Event
		err  string
	}{
		{
			name: "new event",
			evt: Event{
				id32Bit: ID(6000),
				name:    "new_event",
				dependencies: Dependencies{
					events: []ID{
						PrintNetSeqOps,
						DoInitModule,
					},
				},
				sets: []string{"signatures"},
			},
		},
		{
			name: "event id already exist",
			evt: Event{
				id32Bit: ID(700),
				name:    "new_event",
				dependencies: Dependencies{
					events: []ID{
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
			evt: Event{
				id32Bit: ID(6001),
				name:    "net_packet",
				dependencies: Dependencies{
					events: []ID{
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
			err := Core.Add(test.evt.GetID32Bit(), test.evt)
			if err != nil {
				assert.ErrorContains(t, err, test.err)
				return
			}

			id, ok := Core.GetEventIDByName(test.evt.GetName())
			assert.True(t, ok)

			event := Core.GetEventByID(id)
			assert.Equal(t, test.evt, event)
		})
	}
}

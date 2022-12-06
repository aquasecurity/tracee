package events

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewEventDefinition(t *testing.T) {
	expected := Event{
		Name: "hooked_seq_ops2",
		Dependencies: dependencies{
			Events: []eventDependency{
				{EventID: PrintNetSeqOps},
				{EventID: DoInitModule},
			},
		},
		Sets: []string{"rules"},
	}

	e := NewEventDefinition("hooked_seq_ops2", []string{"rules"}, []ID{PrintNetSeqOps, DoInitModule})

	assert.Equal(t, expected.Name, e.Name)
	assert.Equal(t, expected.Dependencies, e.Dependencies)
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
				ID32Bit: ID(6000),
				Name:    "new_event",
				Dependencies: dependencies{
					Events: []eventDependency{
						{EventID: PrintNetSeqOps},
						{EventID: DoInitModule},
					},
				},
				Sets: []string{"rules"},
			},
		},
		{
			name: "event id already exist",
			evt: Event{
				ID32Bit: ID(700),
				Name:    "new_event",
				Dependencies: dependencies{
					Events: []eventDependency{
						{EventID: PrintNetSeqOps},
						{EventID: DoInitModule},
					},
				},
				Sets: []string{"rules"},
			},
			err: "error event id already exist: 700",
		},
		{
			name: "event name already exist",
			evt: Event{
				ID32Bit: ID(6001),
				Name:    "net_packet",
				Dependencies: dependencies{
					Events: []eventDependency{
						{EventID: PrintNetSeqOps},
						{EventID: DoInitModule},
					},
				},
				Sets: []string{"rules"},
			},
			err: "error event name already exist: net_packet",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := Definitions.Add(test.evt.ID32Bit, test.evt)
			if err != nil {
				assert.Equal(t, test.err, err.Error())
				return
			}

			id, ok := Definitions.GetID(test.evt.Name)
			assert.True(t, ok)

			event := Definitions.Get(id)
			assert.Equal(t, test.evt, event)
		})
	}

}

package events

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewEvent(t *testing.T) {
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

	e := NewEvent("hooked_seq_ops2", []string{"rules"}, []ID{PrintNetSeqOps, DoInitModule})

	assert.Equal(t, expected.Name, e.Name)
	assert.Equal(t, expected.Dependencies, e.Dependencies)
}

func TestAdd(t *testing.T) {
	e := Event{
		ID32Bit: ID(6000),
		Name:    "new_event",
		Dependencies: dependencies{
			Events: []eventDependency{
				{EventID: PrintNetSeqOps},
				{EventID: DoInitModule},
			},
		},
		Sets: []string{"rules"},
	}

	Definitions.Add(6000, e)

	id, ok := Definitions.GetID("new_event")
	assert.True(t, ok)

	event := Definitions.Get(id)

	assert.Equal(t, e, event)
}

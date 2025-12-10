package events

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewDefinition(t *testing.T) {
	t.Parallel()

	expectedDefinition := Definition{
		name: "hooked_seq_ops2",
		dependencies: NewDependencyStrategy(Dependencies{
			ids:          []ID{PrintNetSeqOps, DoInitModule},
			kSymbols:     []KSymbol{},
			probes:       []Probe{},
			tailCalls:    []TailCall{},
			capabilities: Capabilities{},
		}),
		sets: []string{"signatures"},
	}

	eventDefinition := NewDefinition(
		0,
		Sys32Undefined,
		"hooked_seq_ops2",
		version,
		"",
		false,
		false,
		[]string{"signatures"},
		NewDependencyStrategy(NewDependencies(
			[]ID{PrintNetSeqOps, DoInitModule},
			[]KSymbol{},
			[]Probe{},
			[]TailCall{},
			Capabilities{},
		)),
		[]DataField{},
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
				dependencies: NewDependencyStrategy(Dependencies{
					ids: []ID{
						PrintNetSeqOps,
						DoInitModule,
					},
				}),
				sets: []string{"signatures"},
			},
		},
		{
			name: "definition id already exists",
			evt: Definition{
				id32Bit: ID(700),
				name:    "new_event",
				dependencies: NewDependencyStrategy(Dependencies{
					ids: []ID{
						PrintNetSeqOps,
						DoInitModule,
					},
				}),
				sets: []string{"signatures"},
			},
			err: "definition id already exists: 700",
		},
		{
			name: "definition name already exists",
			evt: Definition{
				id32Bit: ID(6001),
				name:    "net_packet",
				dependencies: NewDependencyStrategy(Dependencies{
					ids: []ID{
						PrintNetSeqOps,
						DoInitModule,
					},
				}),
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

func TestIsDetector(t *testing.T) {
	t.Parallel()

	t.Run("predefined detector event", func(t *testing.T) {
		// Create a definition with ID in the predefined detector range
		def := Definition{
			id:   ID(StartPredefinedDetectorID + 10), // 3510
			name: "test_detector_event",
		}
		assert.True(t, def.IsDetector(), "event in predefined detector range should be a detector")
	})

	t.Run("dynamic detector event", func(t *testing.T) {
		// Create a definition with ID in the dynamic detector range
		def := Definition{
			id:   ID(StartDetectorID + 100), // 7600
			name: "test_dynamic_detector",
		}
		assert.True(t, def.IsDetector(), "event in dynamic detector range should be a detector")
	})

	t.Run("core event", func(t *testing.T) {
		// Create a definition with ID in the core range
		def := Definition{
			id:   ID(1), // Core event
			name: "test_core_event",
		}
		assert.False(t, def.IsDetector(), "core event should not be a detector")
	})

	t.Run("userspace extended event", func(t *testing.T) {
		// Create a definition with ID in the userspace extended range
		def := Definition{
			id:   ID(StartUserSpaceExtendedID + 50), // 3050
			name: "test_userspace_event",
		}
		assert.False(t, def.IsDetector(), "userspace extended event should not be a detector")
	})

	t.Run("signature extended event", func(t *testing.T) {
		// Create a definition with ID in the signature extended range
		def := Definition{
			id:   ID(StartSignatureExtendedID + 50), // 7050
			name: "test_signature_event",
		}
		assert.False(t, def.IsDetector(), "signature extended event should not be a detector")
	})

	t.Run("boundary at predefined detector start", func(t *testing.T) {
		def := Definition{
			id:   ID(StartPredefinedDetectorID), // 3500
			name: "test_boundary",
		}
		assert.True(t, def.IsDetector(), "event at start of predefined detector range should be a detector")
	})

	t.Run("boundary at predefined detector end", func(t *testing.T) {
		def := Definition{
			id:   ID(MaxPredefinedDetectorID), // 3999
			name: "test_boundary",
		}
		assert.True(t, def.IsDetector(), "event at end of predefined detector range should be a detector")
	})

	t.Run("boundary at dynamic detector start", func(t *testing.T) {
		def := Definition{
			id:   ID(StartDetectorID), // 7500
			name: "test_boundary",
		}
		assert.True(t, def.IsDetector(), "event at start of dynamic detector range should be a detector")
	})

	t.Run("boundary at dynamic detector end", func(t *testing.T) {
		def := Definition{
			id:   ID(MaxDetectorID), // 7999
			name: "test_boundary",
		}
		assert.True(t, def.IsDetector(), "event at end of dynamic detector range should be a detector")
	})

	t.Run("just before predefined detector range", func(t *testing.T) {
		def := Definition{
			id:   ID(StartPredefinedDetectorID - 1), // 3499
			name: "test_not_detector",
		}
		assert.False(t, def.IsDetector(), "event just before predefined detector range should not be a detector")
	})

	t.Run("just after predefined detector range", func(t *testing.T) {
		def := Definition{
			id:   ID(MaxPredefinedDetectorID + 1), // 4000
			name: "test_not_detector",
		}
		assert.False(t, def.IsDetector(), "event just after predefined detector range should not be a detector")
	})
}

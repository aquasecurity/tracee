package detectors

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/parsers"
	"github.com/aquasecurity/tracee/detectors/testutil"
)

func TestPtraceCodeInjection_OnEvent(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		event         *v1beta1.Event
		expectedMatch bool
	}{
		{
			name: "PTRACE_POKETEXT - should detect",
			event: &v1beta1.Event{
				Id:   v1beta1.EventId_ptrace,
				Name: "ptrace",
				Data: []*v1beta1.EventValue{
					v1beta1.NewInt32Value("request", int32(parsers.PTRACE_POKETEXT.Value())),
				},
			},
			expectedMatch: true,
		},
		{
			name: "PTRACE_POKEDATA - should detect",
			event: &v1beta1.Event{
				Id:   v1beta1.EventId_ptrace,
				Name: "ptrace",
				Data: []*v1beta1.EventValue{
					v1beta1.NewInt32Value("request", int32(parsers.PTRACE_POKEDATA.Value())),
				},
			},
			expectedMatch: true,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			detector := &PtraceCodeInjection{}
			params := detection.DetectorParams{
				Logger: &testutil.MockLogger{},
			}
			err := detector.Init(params)
			require.NoError(t, err)

			// In real usage, DataFilters ensure only POKETEXT/POKEDATA events reach OnEvent()
			outputs, err := detector.OnEvent(context.Background(), tc.event)

			require.NoError(t, err)

			if tc.expectedMatch {
				assert.Len(t, outputs, 1, "Expected one detection output")
				assert.Nil(t, outputs[0].Data, "No custom data expected")
			}
		})
	}
}

func TestPtraceCodeInjection_Definition(t *testing.T) {
	t.Parallel()

	detector := &PtraceCodeInjection{}
	def := detector.GetDefinition()

	// Verify basic metadata
	assert.Equal(t, "TRC-103", def.ID)
	assert.Equal(t, "ptrace_code_injection", def.ProducedEvent.Name)
	assert.NotNil(t, def.ThreatMetadata)
	assert.Equal(t, v1beta1.Severity_HIGH, def.ThreatMetadata.Severity)
	assert.Equal(t, "T1055.008", def.ThreatMetadata.Mitre.Technique.Id)

	// Verify event requirements
	require.Len(t, def.Requirements.Events, 1)
	eventReq := def.Requirements.Events[0]
	assert.Equal(t, "ptrace", eventReq.Name)
	assert.Equal(t, detection.DependencyRequired, eventReq.Dependency)

	// Verify DataFilters contain POKETEXT and POKEDATA
	require.Len(t, eventReq.DataFilters, 2)
	assert.Contains(t, eventReq.DataFilters[0], "request=")
	assert.Contains(t, eventReq.DataFilters[1], "request=")

	// Verify auto-populate settings
	assert.True(t, def.AutoPopulate.Threat)
	assert.True(t, def.AutoPopulate.DetectedFrom)
}

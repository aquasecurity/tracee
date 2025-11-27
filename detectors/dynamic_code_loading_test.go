package detectors

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func TestDynamicCodeLoading_OnEvent(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		event         *v1beta1.Event
		expectedMatch bool
	}{
		{
			name: "ProtAlertMprotectWXToX - should detect",
			event: &v1beta1.Event{
				Id:   v1beta1.EventId_mem_prot_alert,
				Name: "mem_prot_alert",
				Data: []*v1beta1.EventValue{
					v1beta1.NewUInt32Value("alert", protAlertMprotectWXToX),
				},
			},
			expectedMatch: true,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			detector := &DynamicCodeLoading{}
			params := detection.DetectorParams{
				Logger: &mockLogger{},
			}
			err := detector.Init(params)
			require.NoError(t, err)

			// In real usage, DataFilters ensure only ProtAlertMprotectWXToX events reach OnEvent()
			outputs, err := detector.OnEvent(context.Background(), tc.event)

			require.NoError(t, err)

			if tc.expectedMatch {
				assert.Len(t, outputs, 1, "Expected one detection output")
				assert.Nil(t, outputs[0].Data, "No custom data expected")
			}
		})
	}
}

func TestDynamicCodeLoading_Definition(t *testing.T) {
	t.Parallel()

	detector := &DynamicCodeLoading{}
	def := detector.GetDefinition()

	// Verify basic metadata
	assert.Equal(t, "TRC-104", def.ID)
	assert.Equal(t, "dynamic_code_loading_detector", def.ProducedEvent.Name)
	assert.NotNil(t, def.ThreatMetadata)
	assert.Equal(t, v1beta1.Severity_MEDIUM, def.ThreatMetadata.Severity)
	assert.Equal(t, "T1027.002", def.ThreatMetadata.Mitre.Technique.Id)

	// Verify event requirements
	require.Len(t, def.Requirements.Events, 1)
	eventReq := def.Requirements.Events[0]
	assert.Equal(t, "mem_prot_alert", eventReq.Name)
	assert.Equal(t, detection.DependencyRequired, eventReq.Dependency)

	// Verify DataFilters contain ProtAlertMprotectWXToX
	require.Len(t, eventReq.DataFilters, 1)
	assert.Contains(t, eventReq.DataFilters[0], "alert=")

	// Verify auto-populate settings
	assert.True(t, def.AutoPopulate.Threat)
	assert.True(t, def.AutoPopulate.DetectedFrom)
}

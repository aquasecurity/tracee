package detectors

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/detectors/testutil"
)

func TestDynamicCodeLoading_OnEvent(t *testing.T) {
	t.Parallel()

	detector := &DynamicCodeLoading{}
	params := detection.DetectorParams{
		Logger: &testutil.MockLogger{},
	}
	err := detector.Init(params)
	require.NoError(t, err)

	t.Run("ProtAlertMprotectWXToX - should detect", func(t *testing.T) {
		event := &v1beta1.Event{
			Id:   v1beta1.EventId_mem_prot_alert,
			Name: "mem_prot_alert",
			Data: []*v1beta1.EventValue{
				v1beta1.NewUInt32Value("alert", protAlertMprotectWXToX),
			},
		}

		// In real usage, DataFilters ensure only ProtAlertMprotectWXToX events reach OnEvent()
		outputs, err := detector.OnEvent(context.Background(), event)

		require.NoError(t, err)
		assert.Len(t, outputs, 1, "Expected one detection output")
		assert.Nil(t, outputs[0].Data, "No custom data expected")
	})

	t.Run("other alert types filtered by DataFilter in production", func(t *testing.T) {
		// This test documents that OnEvent relies on the DataFilter "alert=4" to filter events
		// In production, only ProtAlertMprotectWXToX (4) events reach OnEvent
		// If other alert types somehow reach OnEvent (e.g., in unit tests), they would trigger
		event := &v1beta1.Event{
			Id:   v1beta1.EventId_mem_prot_alert,
			Name: "mem_prot_alert",
			Data: []*v1beta1.EventValue{
				v1beta1.NewUInt32Value("alert", 1), // ProtAlertMmapWX (different alert type)
			},
		}

		outputs, err := detector.OnEvent(context.Background(), event)

		require.NoError(t, err)
		// OnEvent doesn't check alert type - it trusts the DataFilter
		// So even wrong alert types would trigger if they bypass the filter
		assert.Len(t, outputs, 1, "OnEvent always detects (relies on DataFilter for filtering)")
	})
}

func TestDynamicCodeLoading_Definition(t *testing.T) {
	t.Parallel()

	detector := &DynamicCodeLoading{}
	def := detector.GetDefinition()

	// Verify basic metadata
	assert.Equal(t, "TRC-104", def.ID)
	assert.Equal(t, "dynamic_code_loading", def.ProducedEvent.Name)
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

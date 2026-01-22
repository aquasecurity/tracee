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

func TestDroppedExecutable_OnEvent(t *testing.T) {
	t.Parallel()

	// ELF magic bytes
	elfMagic := []byte{0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00}
	nonElfBytes := []byte{0x50, 0x4b, 0x03, 0x04} // ZIP magic

	testCases := []struct {
		name          string
		bytes         []byte
		pathname      string
		expectedMatch bool
	}{
		{
			name:          "ELF written to /tmp - should detect",
			bytes:         elfMagic,
			pathname:      "/tmp/malware",
			expectedMatch: true,
		},
		{
			name:          "ELF written to /var - should detect",
			bytes:         elfMagic,
			pathname:      "/var/lib/suspicious",
			expectedMatch: true,
		},
		{
			name:          "ELF to memory path - should not detect",
			bytes:         elfMagic,
			pathname:      "memfd:test",
			expectedMatch: false,
		},
		{
			name:          "ELF to /dev/shm - should not detect",
			bytes:         elfMagic,
			pathname:      "/dev/shm/test",
			expectedMatch: false,
		},
		{
			name:          "non-ELF file - should not detect",
			bytes:         nonElfBytes,
			pathname:      "/tmp/archive.zip",
			expectedMatch: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			detector := &DroppedExecutable{}
			params := detection.DetectorParams{
				Logger: &testutil.MockLogger{},
			}
			err := detector.Init(params)
			require.NoError(t, err)

			event := &v1beta1.Event{
				Id:   v1beta1.EventId_magic_write,
				Name: "magic_write",
				Workload: &v1beta1.Workload{
					Container: &v1beta1.Container{
						Id:      "test-container",
						Started: true,
					},
				},
				Data: []*v1beta1.EventValue{
					v1beta1.NewBytesValue("bytes", tc.bytes),
					v1beta1.NewStringValue("pathname", tc.pathname),
				},
			}

			outputs, err := detector.OnEvent(context.Background(), event)
			require.NoError(t, err)

			if tc.expectedMatch {
				assert.Len(t, outputs, 1, "Expected detection")
				require.Len(t, outputs[0].Data, 1)
				assert.Equal(t, "path", outputs[0].Data[0].Name)

				// Extract path from output
				path := testutil.GetOutputData(outputs[0], "path")
				assert.Equal(t, tc.pathname, path)
			} else {
				assert.Len(t, outputs, 0, "Expected no detection")
			}
		})
	}
}

func TestDroppedExecutable_Definition(t *testing.T) {
	t.Parallel()

	detector := &DroppedExecutable{}
	def := detector.GetDefinition()

	assert.Equal(t, "TRC-1022", def.ID)
	assert.Equal(t, "dropped_executable", def.ProducedEvent.Name)
	assert.NotNil(t, def.ThreatMetadata)
	assert.Equal(t, v1beta1.Severity_MEDIUM, def.ThreatMetadata.Severity)
	assert.Equal(t, "T1036", def.ThreatMetadata.Mitre.Technique.Id)

	require.Len(t, def.Requirements.Events, 1)
	eventReq := def.Requirements.Events[0]
	assert.Equal(t, "magic_write", eventReq.Name)
	assert.Equal(t, detection.DependencyRequired, eventReq.Dependency)

	// Verify container=started filter (critical for parity)
	require.Len(t, eventReq.ScopeFilters, 1)
	assert.Equal(t, "container=started", eventReq.ScopeFilters[0])

	// Verify output schema
	require.Len(t, def.ProducedEvent.Fields, 1)
	assert.Equal(t, "path", def.ProducedEvent.Fields[0].Name)

	assert.True(t, def.AutoPopulate.Threat)
	assert.True(t, def.AutoPopulate.DetectedFrom)
}

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

func TestHiddenFileCreated_GetDefinition(t *testing.T) {
	detector := &HiddenFileCreated{}
	def := detector.GetDefinition()

	assert.Equal(t, "TRC-1015", def.ID)
	assert.Len(t, def.Requirements.Events, 1)
	assert.Equal(t, "magic_write", def.Requirements.Events[0].Name)
	assert.Equal(t, detection.DependencyRequired, def.Requirements.Events[0].Dependency)

	// Check produced event
	assert.Equal(t, "hidden_file_created", def.ProducedEvent.Name)
	assert.Contains(t, def.ProducedEvent.Description, "Hidden executable")

	// Check threat metadata matches original signature
	require.NotNil(t, def.ThreatMetadata)
	assert.Equal(t, "Hidden executable creation detected", def.ThreatMetadata.Name)
	assert.Equal(t, v1beta1.Severity_MEDIUM, def.ThreatMetadata.Severity)
	assert.Equal(t, "defense-evasion", def.ThreatMetadata.Properties["Category"])

	require.NotNil(t, def.ThreatMetadata.Mitre)
	assert.Equal(t, "Defense Evasion", def.ThreatMetadata.Mitre.Tactic.Name)
	assert.Equal(t, "T1564.001", def.ThreatMetadata.Mitre.Technique.Id)
	assert.Equal(t, "Hidden Files and Directories", def.ThreatMetadata.Mitre.Technique.Name)
}

func TestHiddenFileCreated_Init(t *testing.T) {
	detector := &HiddenFileCreated{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)
}

func TestHiddenFileCreated_OnEvent_HiddenELF(t *testing.T) {
	detector := &HiddenFileCreated{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)

	// ELF magic number: 0x7F, 'E', 'L', 'F'
	elfBytes := []byte{127, 69, 76, 70}

	testCases := []struct {
		name         string
		pathname     string
		shouldDetect bool
	}{
		{"hidden_in_bin", "/bin/.bin", true},
		{"hidden_in_home", "/home/user/.hidden_exec", true},
		{"hidden_in_tmp", "/tmp/.backdoor", true},
		{"not_hidden", "/bin/ls", false},
		{"not_hidden_but_has_dot", "/etc/init.d/service", false},
	}

	ctx := context.Background()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			inputEvent := &v1beta1.Event{
				Id: v1beta1.EventId_magic_write,
				Data: []*v1beta1.EventValue{
					v1beta1.NewStringValue("pathname", tc.pathname),
					v1beta1.NewBytesValue("bytes", elfBytes),
				},
			}

			outputEvents, err := detector.OnEvent(ctx, inputEvent)

			require.NoError(t, err)
			if tc.shouldDetect {
				require.Len(t, outputEvents, 1, "Should detect for %s", tc.name)
				assert.NotNil(t, outputEvents[0])
			} else {
				assert.Len(t, outputEvents, 0, "Should not detect for %s", tc.name)
			}
		})
	}
}

func TestHiddenFileCreated_OnEvent_NotELF(t *testing.T) {
	detector := &HiddenFileCreated{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)

	// Not ELF magic number
	notElfBytes := []byte{0, 0, 0, 0}

	inputEvent := &v1beta1.Event{
		Id: v1beta1.EventId_magic_write,
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", "/bin/.bin"),
			v1beta1.NewBytesValue("bytes", notElfBytes),
		},
	}

	ctx := context.Background()
	outputEvents, err := detector.OnEvent(ctx, inputEvent)

	require.NoError(t, err)
	assert.Len(t, outputEvents, 0, "Should not detect non-ELF file")
}

func TestHiddenFileCreated_OnEvent_MissingFields(t *testing.T) {
	detector := &HiddenFileCreated{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)

	ctx := context.Background()
	elfBytes := []byte{127, 69, 76, 70}

	testCases := []struct {
		name  string
		event *v1beta1.Event
	}{
		{
			"missing_pathname",
			&v1beta1.Event{
				Id: v1beta1.EventId_magic_write,
				Data: []*v1beta1.EventValue{
					v1beta1.NewBytesValue("bytes", elfBytes),
				},
			},
		},
		{
			"missing_bytes",
			&v1beta1.Event{
				Id: v1beta1.EventId_magic_write,
				Data: []*v1beta1.EventValue{
					v1beta1.NewStringValue("pathname", "/bin/.bin"),
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			outputEvents, err := detector.OnEvent(ctx, tc.event)

			// Should not error, just no detection
			require.NoError(t, err)
			assert.Len(t, outputEvents, 0)
		})
	}
}

func TestHiddenFileCreated_OnEvent_MultipleWrites(t *testing.T) {
	detector := &HiddenFileCreated{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)

	ctx := context.Background()
	elfBytes := []byte{127, 69, 76, 70}

	// Multiple writes of hidden ELF files should each trigger detection
	for i := 0; i < 3; i++ {
		inputEvent := &v1beta1.Event{
			Id: v1beta1.EventId_magic_write,
			Data: []*v1beta1.EventValue{
				v1beta1.NewStringValue("pathname", "/bin/.bin"),
				v1beta1.NewBytesValue("bytes", elfBytes),
			},
		}

		outputEvents, err := detector.OnEvent(ctx, inputEvent)
		require.NoError(t, err)
		require.Len(t, outputEvents, 1, "Write operation %d should produce detection", i+1)
	}
}

func TestHiddenFileCreated_Close(t *testing.T) {
	detector := &HiddenFileCreated{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)

	err = detector.Close()
	assert.NoError(t, err)
}

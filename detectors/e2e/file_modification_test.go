//go:build e2e

package e2e

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/detectors/testutil"
)

func TestE2eFileModification_GetDefinition(t *testing.T) {
	detector := &E2eFileModification{}
	def := detector.GetDefinition()

	assert.Equal(t, "FILE_MODIFICATION", def.ID)
	assert.Len(t, def.Requirements.Events, 1)
	assert.Equal(t, "file_modification", def.Requirements.Events[0].Name)
	assert.Equal(t, "FILE_MODIFICATION", def.ProducedEvent.Name)
}

func TestE2eFileModification_OnEvent_Match(t *testing.T) {
	detector := &E2eFileModification{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)

	// Create file_modification event with matching file_path
	inputEvent := &v1beta1.Event{
		Name: "file_modification",
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("file_path", "/tmp/file_modification.txt"),
		},
	}

	ctx := context.Background()
	outputEvents, err := detector.OnEvent(ctx, inputEvent)

	require.NoError(t, err)
	require.Len(t, outputEvents, 1)
}

func TestE2eFileModification_OnEvent_NoMatch(t *testing.T) {
	detector := &E2eFileModification{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)

	// Create file_modification event with non-matching file_path
	inputEvent := &v1beta1.Event{
		Name: "file_modification",
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("file_path", "/tmp/other_file.txt"),
		},
	}

	ctx := context.Background()
	outputEvents, err := detector.OnEvent(ctx, inputEvent)

	require.NoError(t, err)
	assert.Empty(t, outputEvents)
}

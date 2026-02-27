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

func TestE2eVfsWrite_GetDefinition(t *testing.T) {
	detector := &E2eVfsWrite{}
	def := detector.GetDefinition()

	assert.Equal(t, "VFS_WRITE", def.ID)
	assert.Len(t, def.Requirements.Events, 1)
	assert.Equal(t, "vfs_write", def.Requirements.Events[0].Name)
	assert.Equal(t, "VFS_WRITE", def.ProducedEvent.Name)
}

func TestE2eVfsWrite_OnEvent_Match(t *testing.T) {
	detector := &E2eVfsWrite{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)

	// Create vfs_write event with matching pathname
	inputEvent := &v1beta1.Event{
		Name: "vfs_write",
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", "/tmp/vfs_write.txt"),
		},
	}

	ctx := context.Background()
	outputEvents, err := detector.OnEvent(ctx, inputEvent)

	require.NoError(t, err)
	require.Len(t, outputEvents, 1)
}

func TestE2eVfsWrite_OnEvent_NoMatch(t *testing.T) {
	detector := &E2eVfsWrite{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)

	// Create vfs_write event with non-matching pathname
	inputEvent := &v1beta1.Event{
		Name: "vfs_write",
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", "/tmp/other_file.txt"),
		},
	}

	ctx := context.Background()
	outputEvents, err := detector.OnEvent(ctx, inputEvent)

	require.NoError(t, err)
	assert.Empty(t, outputEvents)
}

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

func TestE2eSecurityPathNotify_GetDefinition(t *testing.T) {
	detector := &E2eSecurityPathNotify{}
	def := detector.GetDefinition()

	assert.Equal(t, "SECURITY_PATH_NOTIFY", def.ID)
	assert.Len(t, def.Requirements.Events, 1)
	assert.Equal(t, "security_path_notify", def.Requirements.Events[0].Name)
	assert.Equal(t, "SECURITY_PATH_NOTIFY", def.ProducedEvent.Name)
}

func TestE2eSecurityPathNotify_OnEvent_AllNotifyTypesFound(t *testing.T) {
	detector := &E2eSecurityPathNotify{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)

	ctx := context.Background()

	// First event - dnotify
	dnotifyEvent := &v1beta1.Event{
		Name: "security_path_notify",
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", "/tmp/dnotify_test"),
		},
	}
	_, err = detector.OnEvent(ctx, dnotifyEvent)
	require.NoError(t, err)

	// Second event - inotify
	inotifyEvent := &v1beta1.Event{
		Name: "security_path_notify",
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", "/tmp/inotify_test"),
		},
	}
	_, err = detector.OnEvent(ctx, inotifyEvent)
	require.NoError(t, err)

	// Third event - fanotify (should trigger detection)
	fanotifyEvent := &v1beta1.Event{
		Name: "security_path_notify",
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", "/tmp/fanotify_test"),
		},
	}
	outputEvents, err := detector.OnEvent(ctx, fanotifyEvent)
	require.NoError(t, err)
	require.Len(t, outputEvents, 1)
}

func TestE2eSecurityPathNotify_OnEvent_PartialNotifyTypes_NoDetection(t *testing.T) {
	detector := &E2eSecurityPathNotify{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)

	ctx := context.Background()

	// Only dnotify - should not trigger detection
	dnotifyEvent := &v1beta1.Event{
		Name: "security_path_notify",
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", "/tmp/dnotify_test"),
		},
	}
	outputEvents, err := detector.OnEvent(ctx, dnotifyEvent)
	require.NoError(t, err)
	assert.Empty(t, outputEvents)
}

func TestE2eSecurityPathNotify_OnEvent_UnrelatedPath_NoDetection(t *testing.T) {
	detector := &E2eSecurityPathNotify{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)

	ctx := context.Background()

	// Unrelated path - should not update state
	event := &v1beta1.Event{
		Name: "security_path_notify",
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", "/tmp/other_test"),
		},
	}
	outputEvents, err := detector.OnEvent(ctx, event)
	require.NoError(t, err)
	assert.Empty(t, outputEvents)
}

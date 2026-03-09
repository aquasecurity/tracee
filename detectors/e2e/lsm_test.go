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

func TestE2eLsm_GetDefinition(t *testing.T) {
	detector := &E2eLsm{}
	def := detector.GetDefinition()

	assert.Equal(t, "LSM_TEST", def.ID)
	assert.Len(t, def.Requirements.Events, 1)
	assert.Equal(t, "lsm_test", def.Requirements.Events[0].Name)
	assert.Equal(t, detection.DependencyRequired, def.Requirements.Events[0].Dependency)
	assert.Equal(t, "LSM_TEST", def.ProducedEvent.Name)
}

func TestE2eLsm_Init(t *testing.T) {
	detector := &E2eLsm{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)
}

func TestE2eLsm_OnEvent(t *testing.T) {
	detector := &E2eLsm{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)

	// Create lsm_test event
	inputEvent := &v1beta1.Event{
		Name: "lsm_test",
	}

	ctx := context.Background()
	outputEvents, err := detector.OnEvent(ctx, inputEvent)

	require.NoError(t, err)
	require.Len(t, outputEvents, 1)
}

func TestE2eLsm_Close(t *testing.T) {
	detector := &E2eLsm{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)

	err = detector.Close()
	assert.NoError(t, err)
}

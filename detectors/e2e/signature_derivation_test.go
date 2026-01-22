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

func TestE2eSignatureDerivation_GetDefinition(t *testing.T) {
	detector := &E2eSignatureDerivation{}
	def := detector.GetDefinition()

	assert.Equal(t, "SIGNATURE_DERIVATION", def.ID)
	assert.Len(t, def.Requirements.Events, 1)
	assert.Equal(t, "FILE_MODIFICATION", def.Requirements.Events[0].Name)
	assert.Equal(t, "SIGNATURE_DERIVATION", def.ProducedEvent.Name)
}

func TestE2eSignatureDerivation_OnEvent(t *testing.T) {
	detector := &E2eSignatureDerivation{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)

	// Create FILE_MODIFICATION event (from another detector)
	inputEvent := &v1beta1.Event{
		Name: "FILE_MODIFICATION",
	}

	ctx := context.Background()
	outputEvents, err := detector.OnEvent(ctx, inputEvent)

	require.NoError(t, err)
	require.Len(t, outputEvents, 1)
}

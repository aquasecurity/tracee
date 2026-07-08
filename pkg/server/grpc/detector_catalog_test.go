package grpc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/pkg/cmd/initialize/sigs"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/signatures/signature"
	"github.com/aquasecurity/tracee/types/detect"
)

func registerCatalogTestDetectors(t *testing.T) {
	t.Helper()

	detectorDef := events.NewDefinition(
		events.ID(99998),
		events.Sys32Undefined,
		"catalog_test_detector",
		events.NewVersion(1, 0, 0),
		"detector description",
		false,
		false,
		[]string{"detectors", "default"},
		events.NewDependencyStrategy(events.NewDependencies(
			[]events.ID{},
			[]events.KSymbol{},
			[]events.Probe{},
			[]events.TailCall{},
			events.Capabilities{},
		)),
		[]events.DataField{},
		map[string]interface{}{
			"detectorID": "DET-001",
		},
	)

	require.NoError(t, events.Core.Add(events.ID(99998), detectorDef))

	testSignature := signature.FakeSignature{
		FakeGetMetadata: func() (detect.SignatureMetadata, error) {
			return detect.SignatureMetadata{
				ID:          "TRH-test-001",
				Name:        "Test Signature",
				EventName:   "catalog_test_sig",
				Description: "catalog test description",
				Version:     "1.0.0",
			}, nil
		},
		FakeGetSelectedEvents: func() ([]detect.SignatureEventSelector, error) {
			return []detect.SignatureEventSelector{
				{Name: "sched_process_exec", Source: "tracee", Origin: "*"},
			}, nil
		},
	}

	sigs.CreateEventsFromSignatures(events.ID(99999), []detect.Signature{&testSignature})
}

func TestDetectorsCatalog(t *testing.T) {
	registerCatalogTestDetectors(t)

	t.Run("returns catalog identity", func(t *testing.T) {
		entries, err := buildDetectorsCatalog(&pb.GetDetectorsCatalogRequest{})
		require.NoError(t, err)

		var found *pb.DetectorCatalogEntry
		for _, entry := range entries {
			if entry.GetEventName() == "catalog_test_sig" {
				found = entry
				break
			}
		}

		require.NotNil(t, found)
		assert.Equal(t, "TRH-test-001", found.GetDetectorId())
		assert.Equal(t, "Test Signature", found.GetDetectorName())
		assert.Equal(t, "catalog_test_sig", found.GetEventName())
		assert.Equal(t, "catalog test description", found.GetDescription())
		assert.Contains(t, found.GetTags(), "signatures")
		assert.Equal(t, "TRH-test-001", found.GetProperties()["signatureID"])
		assert.Equal(t, "Test Signature", found.GetProperties()["signatureName"])

		var detectorFound *pb.DetectorCatalogEntry
		for _, entry := range entries {
			if entry.GetEventName() == "catalog_test_detector" {
				detectorFound = entry
				break
			}
		}
		require.NotNil(t, detectorFound)
		assert.Equal(t, "DET-001", detectorFound.GetDetectorId())
		assert.Equal(t, "catalog_test_detector", detectorFound.GetDetectorName())
		assert.Contains(t, detectorFound.GetTags(), "detectors")
	})

	t.Run("filters by detector id and event name", func(t *testing.T) {
		entries, err := buildDetectorsCatalog(&pb.GetDetectorsCatalogRequest{
			DetectorIds: []string{"TRH-test-001"},
		})
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.Equal(t, "catalog_test_sig", entries[0].GetEventName())

		entries, err = buildDetectorsCatalog(&pb.GetDetectorsCatalogRequest{
			EventNames: []string{"catalog_test_sig"},
		})
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.Equal(t, "TRH-test-001", entries[0].GetDetectorId())
	})

	t.Run("rejects unknown filters", func(t *testing.T) {
		_, err := buildDetectorsCatalog(&pb.GetDetectorsCatalogRequest{
			DetectorIds: []string{"TRH-does-not-exist"},
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())

		_, err = buildDetectorsCatalog(&pb.GetDetectorsCatalogRequest{
			EventNames: []string{"does_not_exist_event"},
		})
		require.Error(t, err)
		st, ok = status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("rpc handler", func(t *testing.T) {
		service := &TraceeService{}
		resp, err := service.GetDetectorsCatalog(context.Background(), &pb.GetDetectorsCatalogRequest{
			EventNames: []string{"catalog_test_sig"},
		})
		require.NoError(t, err)
		require.Len(t, resp.GetEntries(), 1)
		assert.Equal(t, "TRH-test-001", resp.GetEntries()[0].GetDetectorId())
	})
}

func TestPropertiesToProtoMap(t *testing.T) {
	t.Parallel()

	result := propertiesToProtoMap(map[string]interface{}{
		"signatureID":   "TRH-1",
		"signatureName": "name",
		"count":         42,
	})
	assert.Equal(t, "TRH-1", result["signatureID"])
	assert.Equal(t, "name", result["signatureName"])
	assert.Equal(t, "42", result["count"])
}

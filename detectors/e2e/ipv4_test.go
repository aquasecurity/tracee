//go:build e2e_net

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

func TestE2eIPv4_GetDefinition(t *testing.T) {
	detector := &E2eIPv4{}
	def := detector.GetDefinition()

	assert.Equal(t, "IPv4", def.ID)
	assert.Len(t, def.Requirements.Events, 1)
	assert.Equal(t, "net_packet_ipv4", def.Requirements.Events[0].Name)
	assert.Equal(t, "IPv4", def.ProducedEvent.Name)
}

func TestE2eIPv4_OnEvent_Match(t *testing.T) {
	detector := &E2eIPv4{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)

	// Create net_packet_ipv4 event with matching data
	inputEvent := &v1beta1.Event{
		Name: "net_packet_ipv4",
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("src", "172.16.17.2"),
			v1beta1.NewStringValue("dst", "172.16.17.1"),
			{
				Name: "proto_ipv4",
				Value: &v1beta1.EventValue_Ipv4{
					Ipv4: &v1beta1.IPv4{
						Version: 4,
						Ihl:     5,
						SrcIp:   "172.16.17.2",
						DstIp:   "172.16.17.1",
					},
				},
			},
		},
	}

	ctx := context.Background()
	outputEvents, err := detector.OnEvent(ctx, inputEvent)

	require.NoError(t, err)
	require.Len(t, outputEvents, 1)
}

func TestE2eIPv4_OnEvent_NoMatch_WrongIP(t *testing.T) {
	detector := &E2eIPv4{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)

	// Create net_packet_ipv4 event with non-matching IPs
	inputEvent := &v1beta1.Event{
		Name: "net_packet_ipv4",
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("src", "10.0.0.1"),
			v1beta1.NewStringValue("dst", "10.0.0.2"),
			{
				Name: "proto_ipv4",
				Value: &v1beta1.EventValue_Ipv4{
					Ipv4: &v1beta1.IPv4{
						Version: 4,
						Ihl:     5,
						SrcIp:   "10.0.0.1",
						DstIp:   "10.0.0.2",
					},
				},
			},
		},
	}

	ctx := context.Background()
	outputEvents, err := detector.OnEvent(ctx, inputEvent)

	require.NoError(t, err)
	assert.Empty(t, outputEvents)
}

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

func TestE2eTCP_GetDefinition(t *testing.T) {
	detector := &E2eTCP{}
	def := detector.GetDefinition()

	assert.Equal(t, "TCP", def.ID)
	assert.Len(t, def.Requirements.Events, 1)
	assert.Equal(t, "net_packet_tcp", def.Requirements.Events[0].Name)
	assert.Equal(t, "TCP", def.ProducedEvent.Name)
}

func TestE2eTCP_OnEvent_Match(t *testing.T) {
	detector := &E2eTCP{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)

	// Create net_packet_tcp event with matching data
	inputEvent := &v1beta1.Event{
		Name: "net_packet_tcp",
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("src", "172.16.17.1"),
			v1beta1.NewStringValue("dst", "172.16.17.2"),
			{
				Name: "proto_tcp",
				Value: &v1beta1.EventValue_Tcp{
					Tcp: &v1beta1.TCP{
						SrcPort: 8090,
						AckFlag: 1,
						RstFlag: 0,
						UrgFlag: 0,
						SynFlag: 0,
						FinFlag: 0,
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

func TestE2eTCP_OnEvent_NoMatch_WrongPort(t *testing.T) {
	detector := &E2eTCP{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)

	// Create net_packet_tcp event with wrong port
	inputEvent := &v1beta1.Event{
		Name: "net_packet_tcp",
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("src", "172.16.17.1"),
			v1beta1.NewStringValue("dst", "172.16.17.2"),
			{
				Name: "proto_tcp",
				Value: &v1beta1.EventValue_Tcp{
					Tcp: &v1beta1.TCP{
						SrcPort: 80, // Wrong port
						AckFlag: 1,
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

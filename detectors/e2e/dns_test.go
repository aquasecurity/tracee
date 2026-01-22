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

func TestE2eDNS_GetDefinition(t *testing.T) {
	detector := &E2eDNS{}
	def := detector.GetDefinition()

	assert.Equal(t, "DNS", def.ID)
	assert.Len(t, def.Requirements.Events, 1)
	assert.Equal(t, "net_packet_dns", def.Requirements.Events[0].Name)
	assert.Equal(t, "DNS", def.ProducedEvent.Name)
}

func TestE2eDNS_OnEvent_AllRecordsFound(t *testing.T) {
	detector := &E2eDNS{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)

	ctx := context.Background()

	// First event with MX record
	mxEvent := &v1beta1.Event{
		Name: "net_packet_dns",
		Data: []*v1beta1.EventValue{
			{
				Name: "proto_dns",
				Value: &v1beta1.EventValue_Dns{
					Dns: &v1beta1.DNS{
						Answers: []*v1beta1.DNSResourceRecord{
							{
								Mx: &v1beta1.DNSMX{
									Name:       "smtp.google.com",
									Preference: 10,
								},
							},
						},
					},
				},
			},
		},
	}
	_, err = detector.OnEvent(ctx, mxEvent)
	require.NoError(t, err)

	// Second event with NS record
	nsEvent := &v1beta1.Event{
		Name: "net_packet_dns",
		Data: []*v1beta1.EventValue{
			{
				Name: "proto_dns",
				Value: &v1beta1.EventValue_Dns{
					Dns: &v1beta1.DNS{
						Answers: []*v1beta1.DNSResourceRecord{
							{
								Ns: "ns1.google.com",
							},
						},
					},
				},
			},
		},
	}
	_, err = detector.OnEvent(ctx, nsEvent)
	require.NoError(t, err)

	// Third event with SOA record - should trigger detection
	soaEvent := &v1beta1.Event{
		Name: "net_packet_dns",
		Data: []*v1beta1.EventValue{
			{
				Name: "proto_dns",
				Value: &v1beta1.EventValue_Dns{
					Dns: &v1beta1.DNS{
						Answers: []*v1beta1.DNSResourceRecord{
							{
								Soa: &v1beta1.DNSSOA{
									Rname: "dns-admin.google.com",
								},
							},
						},
					},
				},
			},
		},
	}
	outputEvents, err := detector.OnEvent(ctx, soaEvent)
	require.NoError(t, err)
	require.Len(t, outputEvents, 1)
}

func TestE2eDNS_OnEvent_PartialRecords_NoDetection(t *testing.T) {
	detector := &E2eDNS{}

	params := detection.DetectorParams{
		Logger:     &testutil.MockLogger{},
		DataStores: &testutil.MockDataStoreRegistry{},
	}

	err := detector.Init(params)
	require.NoError(t, err)

	ctx := context.Background()

	// Only MX record - should not trigger detection
	mxEvent := &v1beta1.Event{
		Name: "net_packet_dns",
		Data: []*v1beta1.EventValue{
			{
				Name: "proto_dns",
				Value: &v1beta1.EventValue_Dns{
					Dns: &v1beta1.DNS{
						Answers: []*v1beta1.DNSResourceRecord{
							{
								Mx: &v1beta1.DNSMX{
									Name:       "smtp.google.com",
									Preference: 10,
								},
							},
						},
					},
				},
			},
		},
	}
	outputEvents, err := detector.OnEvent(ctx, mxEvent)
	require.NoError(t, err)
	assert.Empty(t, outputEvents)
}

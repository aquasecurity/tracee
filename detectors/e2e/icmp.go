//go:build e2e_net

package e2e

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() { registerE2eNet(&E2eICMP{}) }

// E2eICMP is an e2e test detector for testing the net_packet_icmp event.
type E2eICMP struct {
	logger detection.Logger
}

func (d *E2eICMP) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "ICMP",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "net_packet_icmp",
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "ICMP",
			Description: "Network E2E Tests: ICMP",
			Version:     &v1beta1.Version{Major: 0, Minor: 1, Patch: 0},
			Tags:        []string{"e2e", "net"},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *E2eICMP) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Debugw("E2eICMP detector initialized")
	return nil
}

func (d *E2eICMP) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	src, err := v1beta1.GetDataSafe[string](event, "src")
	if err != nil {
		return nil, nil
	}

	dst, err := v1beta1.GetDataSafe[string](event, "dst")
	if err != nil {
		return nil, nil
	}

	// Get proto_icmp data
	var icmp *v1beta1.ICMP
	for _, data := range event.Data {
		if data.Name == "proto_icmp" {
			if v, ok := data.Value.(*v1beta1.EventValue_Icmp); ok {
				icmp = v.Icmp
			}
			break
		}
	}

	if icmp == nil {
		return nil, nil
	}

	// Check values for detection
	if src != "172.16.17.1" || dst != "172.16.17.2" {
		return nil, nil
	}

	if icmp.TypeCode != "EchoReply" {
		return nil, nil
	}

	return detection.Detected(), nil
}

func (d *E2eICMP) Close() error {
	d.logger.Debugw("E2eICMP detector closed")
	return nil
}

//go:build e2e_net

package e2e

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() { registerE2eNet(&E2eUDP{}) }

// E2eUDP is an e2e test detector for testing the net_packet_udp event.
type E2eUDP struct {
	logger detection.Logger
}

func (d *E2eUDP) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "UDP",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "net_packet_udp",
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "UDP",
			Description: "Network E2E Tests: UDP",
			Version:     &v1beta1.Version{Major: 0, Minor: 1, Patch: 0},
			Tags:        []string{"e2e", "net"},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *E2eUDP) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Debugw("E2eUDP detector initialized")
	return nil
}

func (d *E2eUDP) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	src, err := v1beta1.GetDataSafe[string](event, "src")
	if err != nil {
		return nil, nil
	}

	dst, err := v1beta1.GetDataSafe[string](event, "dst")
	if err != nil {
		return nil, nil
	}

	// Get proto_udp data
	var udp *v1beta1.UDP
	for _, data := range event.Data {
		if data.Name == "proto_udp" {
			if v, ok := data.Value.(*v1beta1.EventValue_Udp); ok {
				udp = v.Udp
			}
			break
		}
	}

	if udp == nil {
		return nil, nil
	}

	// Check values for detection
	if src != "172.16.17.2" || dst != "172.16.17.1" {
		return nil, nil
	}

	if udp.DstPort != 8090 {
		return nil, nil
	}

	return detection.Detected(), nil
}

func (d *E2eUDP) Close() error {
	d.logger.Debugw("E2eUDP detector closed")
	return nil
}

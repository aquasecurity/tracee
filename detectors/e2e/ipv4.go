//go:build e2e_net

package e2e

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() { registerE2eNet(&E2eIPv4{}) }

// E2eIPv4 is an e2e test detector for testing the net_packet_ipv4 event.
type E2eIPv4 struct {
	logger detection.Logger
}

func (d *E2eIPv4) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "IPv4",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "net_packet_ipv4",
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "IPv4",
			Description: "Network E2E Tests: IPv4",
			Version:     &v1beta1.Version{Major: 0, Minor: 1, Patch: 0},
			Tags:        []string{"e2e", "net"},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *E2eIPv4) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Debugw("E2eIPv4 detector initialized")
	return nil
}

func (d *E2eIPv4) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	src, err := v1beta1.GetDataSafe[string](event, "src")
	if err != nil {
		return nil, nil
	}

	dst, err := v1beta1.GetDataSafe[string](event, "dst")
	if err != nil {
		return nil, nil
	}

	// Get proto_ipv4 data
	var ipv4 *v1beta1.IPv4
	for _, data := range event.Data {
		if data.Name == "proto_ipv4" {
			if v, ok := data.Value.(*v1beta1.EventValue_Ipv4); ok {
				ipv4 = v.Ipv4
			}
			break
		}
	}

	if ipv4 == nil {
		return nil, nil
	}

	// Check values for detection
	if src != "172.16.17.2" || dst != "172.16.17.1" {
		return nil, nil
	}

	if ipv4.Version != 4 || ipv4.Ihl != 5 ||
		ipv4.SrcIp != "172.16.17.2" ||
		ipv4.DstIp != "172.16.17.1" {
		return nil, nil
	}

	return detection.Detected(), nil
}

func (d *E2eIPv4) Close() error {
	d.logger.Debugw("E2eIPv4 detector closed")
	return nil
}

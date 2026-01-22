//go:build e2e_net

package e2e

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() { registerE2eNet(&E2eIPv6{}) }

// E2eIPv6 is an e2e test detector for testing the net_packet_ipv6 event.
type E2eIPv6 struct {
	logger detection.Logger
}

func (d *E2eIPv6) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "IPv6",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "net_packet_ipv6",
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "IPv6",
			Description: "Network E2E Tests: IPv6",
			Version:     &v1beta1.Version{Major: 0, Minor: 1, Patch: 0},
			Tags:        []string{"e2e", "net"},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *E2eIPv6) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Debugw("E2eIPv6 detector initialized")
	return nil
}

func (d *E2eIPv6) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	src, err := v1beta1.GetDataSafe[string](event, "src")
	if err != nil {
		return nil, nil
	}

	dst, err := v1beta1.GetDataSafe[string](event, "dst")
	if err != nil {
		return nil, nil
	}

	// Get proto_ipv6 data
	var ipv6 *v1beta1.IPv6
	for _, data := range event.Data {
		if data.Name == "proto_ipv6" {
			if v, ok := data.Value.(*v1beta1.EventValue_Ipv6); ok {
				ipv6 = v.Ipv6
			}
			break
		}
	}

	if ipv6 == nil {
		return nil, nil
	}

	// Check values for detection
	if src != "fd6e:a63d:71f:2f4::2" || dst != "fd6e:a63d:71f:2f4::1" {
		return nil, nil
	}

	if ipv6.Version != 6 || ipv6.HopLimit != 64 ||
		ipv6.SrcIp != "fd6e:a63d:71f:2f4::2" ||
		ipv6.DstIp != "fd6e:a63d:71f:2f4::1" {
		return nil, nil
	}

	return detection.Detected(), nil
}

func (d *E2eIPv6) Close() error {
	d.logger.Debugw("E2eIPv6 detector closed")
	return nil
}

//go:build e2e_net

package e2e

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() { registerE2eNet(&E2eICMPv6{}) }

// E2eICMPv6 is an e2e test detector for testing the net_packet_icmpv6 event.
type E2eICMPv6 struct {
	logger detection.Logger
}

func (d *E2eICMPv6) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "ICMPv6",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "net_packet_icmpv6",
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "ICMPv6",
			Description: "Network E2E Tests: ICMPv6",
			Version:     &v1beta1.Version{Major: 0, Minor: 1, Patch: 0},
			Tags:        []string{"e2e", "net"},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *E2eICMPv6) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Debugw("E2eICMPv6 detector initialized")
	return nil
}

func (d *E2eICMPv6) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	src, err := v1beta1.GetDataSafe[string](event, "src")
	if err != nil {
		return nil, nil
	}

	dst, err := v1beta1.GetDataSafe[string](event, "dst")
	if err != nil {
		return nil, nil
	}

	// Get proto_icmpv6 data
	var icmpv6 *v1beta1.ICMPv6
	for _, data := range event.Data {
		if data.Name == "proto_icmpv6" {
			if v, ok := data.Value.(*v1beta1.EventValue_Icmpv6); ok {
				icmpv6 = v.Icmpv6
			}
			break
		}
	}

	if icmpv6 == nil {
		return nil, nil
	}

	// Check values for detection
	if src != "fd6e:a63d:71f:2f4::1" || dst != "fd6e:a63d:71f:2f4::2" {
		return nil, nil
	}

	if icmpv6.TypeCode != "EchoReply" {
		return nil, nil
	}

	return detection.Detected(), nil
}

func (d *E2eICMPv6) Close() error {
	d.logger.Debugw("E2eICMPv6 detector closed")
	return nil
}

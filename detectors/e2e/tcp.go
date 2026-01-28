//go:build e2e_net

package e2e

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() { registerE2eNet(&E2eTCP{}) }

// E2eTCP is an e2e test detector for testing the net_packet_tcp event.
type E2eTCP struct {
	logger detection.Logger
}

func (d *E2eTCP) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TCP",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "net_packet_tcp",
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "TCP",
			Description: "Network E2E Tests: TCP",
			Version:     &v1beta1.Version{Major: 0, Minor: 1, Patch: 0},
			Tags:        []string{"e2e", "net"},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *E2eTCP) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Debugw("E2eTCP detector initialized")
	return nil
}

func (d *E2eTCP) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	src, err := v1beta1.GetDataSafe[string](event, "src")
	if err != nil {
		return nil, nil
	}

	dst, err := v1beta1.GetDataSafe[string](event, "dst")
	if err != nil {
		return nil, nil
	}

	// Get proto_tcp data
	var tcp *v1beta1.TCP
	for _, data := range event.Data {
		if data.Name == "proto_tcp" {
			if v, ok := data.Value.(*v1beta1.EventValue_Tcp); ok {
				tcp = v.Tcp
			}
			break
		}
	}

	if tcp == nil {
		return nil, nil
	}

	// Check values for detection
	if src != "172.16.17.1" || dst != "172.16.17.2" {
		return nil, nil
	}

	if tcp.SrcPort != 8090 ||
		tcp.AckFlag != 1 ||
		tcp.RstFlag != 0 ||
		tcp.UrgFlag != 0 ||
		tcp.SynFlag != 0 ||
		tcp.FinFlag != 0 {
		return nil, nil
	}

	return detection.Detected(), nil
}

func (d *E2eTCP) Close() error {
	d.logger.Debugw("E2eTCP detector closed")
	return nil
}

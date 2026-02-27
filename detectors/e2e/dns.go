//go:build e2e_net

package e2e

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() { registerE2eNet(&E2eDNS{}) }

// E2eDNS is an e2e test detector for testing the net_packet_dns event.
// It is stateful and requires detecting MX, NS, and SOA records.
type E2eDNS struct {
	logger   detection.Logger
	foundMX  bool
	foundNS  bool
	foundSOA bool
}

func (d *E2eDNS) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "DNS",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "net_packet_dns",
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "DNS",
			Description: "Network E2E Tests: DNS",
			Version:     &v1beta1.Version{Major: 0, Minor: 1, Patch: 0},
			Tags:        []string{"e2e", "net"},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *E2eDNS) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.foundMX = false
	d.foundNS = false
	d.foundSOA = false
	d.logger.Debugw("E2eDNS detector initialized")
	return nil
}

func (d *E2eDNS) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Get proto_dns data
	var dns *v1beta1.DNS
	for _, data := range event.Data {
		if data.Name == "proto_dns" {
			if v, ok := data.Value.(*v1beta1.EventValue_Dns); ok {
				dns = v.Dns
			}
			break
		}
	}

	if dns == nil {
		return nil, nil
	}

	if len(dns.Answers) > 0 {
		for _, answer := range dns.Answers {
			// Check if MX works
			if answer.Mx != nil && answer.Mx.Name == "smtp.google.com" && answer.Mx.Preference == 10 {
				d.foundMX = true
				d.logger.Infow("found MX", "name", answer.Mx.Name, "preference", answer.Mx.Preference)
			}
			// Check if NS works
			if answer.Ns == "ns1.google.com" {
				d.foundNS = true
				d.logger.Infow("found NS", "name", answer.Ns)
			}
			// Check if SOA works
			if answer.Soa != nil && answer.Soa.Rname == "dns-admin.google.com" {
				d.foundSOA = true
				d.logger.Infow("found SOA", "name", answer.Soa.Rname)
			}
		}
	}

	if !d.foundMX || !d.foundNS || !d.foundSOA {
		return nil, nil
	}

	// Reset state
	if d.foundMX && d.foundNS && d.foundSOA {
		d.foundMX = false
		d.foundNS = false
		d.foundSOA = false
	}

	return detection.Detected(), nil
}

func (d *E2eDNS) Close() error {
	d.logger.Debugw("E2eDNS detector closed")
	return nil
}

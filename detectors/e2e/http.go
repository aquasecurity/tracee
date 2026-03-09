//go:build e2e_net

package e2e

import (
	"context"
	"strings"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() { registerE2eNet(&E2eHTTP{}) }

// E2eHTTP is an e2e test detector for testing the net_packet_http event.
type E2eHTTP struct {
	logger detection.Logger
}

func (d *E2eHTTP) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "HTTP",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "net_packet_http",
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "HTTP",
			Description: "Network E2E Tests: HTTP",
			Version:     &v1beta1.Version{Major: 0, Minor: 1, Patch: 0},
			Tags:        []string{"e2e", "net"},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *E2eHTTP) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Debugw("E2eHTTP detector initialized")
	return nil
}

func (d *E2eHTTP) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Check process name
	processName := ""
	if event.Workload != nil && event.Workload.Process != nil && event.Workload.Process.Thread != nil {
		processName = event.Workload.Process.Thread.Name
	}

	if processName != "curl" {
		return nil, nil
	}

	// Get proto_http data
	var http *v1beta1.HTTP
	for _, data := range event.Data {
		if data.Name == "proto_http" {
			if v, ok := data.Value.(*v1beta1.EventValue_Http); ok {
				http = v.Http
			}
			break
		}
	}

	if http == nil {
		return nil, nil
	}

	if http.Direction != "request" && http.Direction != "response" {
		return nil, nil
	}

	// Get packet metadata
	var metadata *v1beta1.PacketMetadata
	for _, data := range event.Data {
		if data.Name == "metadata" {
			if v, ok := data.Value.(*v1beta1.EventValue_PacketMetadata); ok {
				metadata = v.PacketMetadata
			}
			break
		}
	}

	if metadata != nil {
		// This test is done in the context of a curl request
		if !((http.Direction == "request" && metadata.Direction == v1beta1.PacketDirection_EGRESS) ||
			(http.Direction == "response" && metadata.Direction == v1beta1.PacketDirection_INGRESS)) {
			d.logger.Infow("direction mismatch", "direction", http.Direction, "packet_direction", metadata.Direction)
			return nil, nil
		}
	}

	if !strings.HasPrefix(http.Protocol, "HTTP/") {
		d.logger.Infow("not HTTP", "protocol", http.Protocol)
		return nil, nil
	}

	return detection.Detected(), nil
}

func (d *E2eHTTP) Close() error {
	d.logger.Debugw("E2eHTTP detector closed")
	return nil
}

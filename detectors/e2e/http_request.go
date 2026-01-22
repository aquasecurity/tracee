//go:build e2e_net

package e2e

import (
	"context"
	"strings"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() { registerE2eNet(&E2eHTTPRequest{}) }

// E2eHTTPRequest is an e2e test detector for testing the net_packet_http_request event.
type E2eHTTPRequest struct {
	logger detection.Logger
}

func (d *E2eHTTPRequest) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "HTTPRequest",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "net_packet_http_request",
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "HTTPRequest",
			Description: "Network E2E Tests: HTTP Request",
			Version:     &v1beta1.Version{Major: 0, Minor: 1, Patch: 0},
			Tags:        []string{"e2e", "net"},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *E2eHTTPRequest) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Debugw("E2eHTTPRequest detector initialized")
	return nil
}

func (d *E2eHTTPRequest) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Check process name
	processName := ""
	if event.Workload != nil && event.Workload.Process != nil && event.Workload.Process.Thread != nil {
		processName = event.Workload.Process.Thread.Name
	}

	if processName != "curl" {
		return nil, nil
	}

	// Get http_request data
	var httpRequest *v1beta1.HTTPRequest
	for _, data := range event.Data {
		if data.Name == "http_request" {
			if v, ok := data.Value.(*v1beta1.EventValue_HttpRequest); ok {
				httpRequest = v.HttpRequest
			}
			break
		}
	}

	if httpRequest == nil {
		return nil, nil
	}

	if !strings.HasPrefix(httpRequest.Protocol, "HTTP/") {
		return nil, nil
	}

	if !strings.HasSuffix(httpRequest.Host, "google.com") {
		d.logger.Infow("not google.com", "host", httpRequest.Host)
		return nil, nil
	}

	return detection.Detected(), nil
}

func (d *E2eHTTPRequest) Close() error {
	d.logger.Debugw("E2eHTTPRequest detector closed")
	return nil
}

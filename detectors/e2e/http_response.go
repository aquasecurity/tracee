//go:build e2e_net

package e2e

import (
	"context"
	"strings"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() { registerE2eNet(&E2eHTTPResponse{}) }

// E2eHTTPResponse is an e2e test detector for testing the net_packet_http_response event.
type E2eHTTPResponse struct {
	logger detection.Logger
}

func (d *E2eHTTPResponse) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "HTTPResponse",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "net_packet_http_response",
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "HTTPResponse",
			Description: "Network E2E Tests: HTTP Response",
			Version:     &v1beta1.Version{Major: 0, Minor: 1, Patch: 0},
			Tags:        []string{"e2e", "net"},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *E2eHTTPResponse) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Debugw("E2eHTTPResponse detector initialized")
	return nil
}

func (d *E2eHTTPResponse) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Get http_response data
	var httpResponse *v1beta1.HTTPResponse
	for _, data := range event.Data {
		if data.Name == "http_response" {
			if v, ok := data.Value.(*v1beta1.EventValue_HttpResponse); ok {
				httpResponse = v.HttpResponse
			}
			break
		}
	}

	if httpResponse == nil {
		return nil, nil
	}

	if !strings.HasPrefix(httpResponse.Protocol, "HTTP/") {
		d.logger.Infow("not HTTP", "protocol", httpResponse.Protocol)
		return nil, nil
	}

	location, ok := httpResponse.Headers["Location"]
	if !ok || location == nil || len(location.Header) == 0 {
		return nil, nil
	}
	if !strings.Contains(location.Header[0], "google.com") {
		d.logger.Infow("not google.com", "location", location.Header[0])
		return nil, nil
	}

	return detection.Detected(), nil
}

func (d *E2eHTTPResponse) Close() error {
	d.logger.Debugw("E2eHTTPResponse detector closed")
	return nil
}

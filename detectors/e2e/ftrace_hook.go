//go:build e2e

package e2e

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() { registerE2e(&E2eFtraceHook{}) }

// E2eFtraceHook is an e2e test detector for testing the ftrace_hook event.
type E2eFtraceHook struct {
	logger detection.Logger
}

func (d *E2eFtraceHook) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "FTRACE_HOOK",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "ftrace_hook",
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "FTRACE_HOOK",
			Description: "Instrumentation events E2E Tests: ftrace_hook",
			Version:     &v1beta1.Version{Major: 0, Minor: 1, Patch: 0},
			Tags:        []string{"e2e"},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *E2eFtraceHook) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Debugw("E2eFtraceHook detector initialized")
	return nil
}

func (d *E2eFtraceHook) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	symbolName, err := v1beta1.GetDataSafe[string](event, "symbol")
	if err != nil {
		return nil, nil
	}

	if symbolName != "commit_creds" {
		return nil, nil
	}

	return detection.Detected(), nil
}

func (d *E2eFtraceHook) Close() error {
	d.logger.Debugw("E2eFtraceHook detector closed")
	return nil
}

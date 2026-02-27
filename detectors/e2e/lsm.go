//go:build e2e

package e2e

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() { registerE2e(&E2eLsm{}) }

// E2eLsm is an e2e test detector for testing the lsm_test event.
type E2eLsm struct {
	logger detection.Logger
}

func (d *E2eLsm) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "LSM_TEST",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "lsm_test",
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "LSM_TEST",
			Description: "Instrumentation events E2E Tests: LSM Test",
			Version:     &v1beta1.Version{Major: 0, Minor: 1, Patch: 0},
			Tags:        []string{"e2e"},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *E2eLsm) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Debugw("E2eLsm detector initialized")
	return nil
}

func (d *E2eLsm) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// The event itself being triggered indicates successful LSM probe functionality
	return detection.Detected(), nil
}

func (d *E2eLsm) Close() error {
	d.logger.Debugw("E2eLsm detector closed")
	return nil
}

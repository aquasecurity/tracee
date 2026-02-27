//go:build e2e

package e2e

import (
	"context"
	"strings"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() { registerE2e(&E2eFileModification{}) }

// E2eFileModification is an e2e test detector for testing the file_modification event.
type E2eFileModification struct {
	logger detection.Logger
}

func (d *E2eFileModification) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "FILE_MODIFICATION",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "file_modification",
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "FILE_MODIFICATION",
			Description: "Instrumentation events E2E Tests: File Modification",
			Version:     &v1beta1.Version{Major: 0, Minor: 1, Patch: 0},
			Tags:        []string{"e2e"},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *E2eFileModification) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Debugw("E2eFileModification detector initialized")
	return nil
}

func (d *E2eFileModification) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	filePath, err := v1beta1.GetDataSafe[string](event, "file_path")
	if err != nil {
		return nil, nil
	}

	// Check expected values from test for detection
	if !strings.HasSuffix(filePath, "/file_modification.txt") {
		return nil, nil
	}

	return detection.Detected(), nil
}

func (d *E2eFileModification) Close() error {
	d.logger.Debugw("E2eFileModification detector closed")
	return nil
}

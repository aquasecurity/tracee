//go:build e2e

package e2e

import (
	"context"
	"strings"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() { registerE2e(&E2eVfsWrite{}) }

// E2eVfsWrite is an e2e test detector for testing the vfs_write event.
type E2eVfsWrite struct {
	logger detection.Logger
}

func (d *E2eVfsWrite) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "VFS_WRITE",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "vfs_write",
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "VFS_WRITE",
			Description: "Instrumentation events E2E Tests: Vfs Write",
			Version:     &v1beta1.Version{Major: 0, Minor: 1, Patch: 0},
			Tags:        []string{"e2e"},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *E2eVfsWrite) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Debugw("E2eVfsWrite detector initialized")
	return nil
}

func (d *E2eVfsWrite) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	filePath, err := v1beta1.GetDataSafe[string](event, "pathname")
	if err != nil {
		return nil, nil
	}

	// Check expected values from test for detection
	if !strings.HasSuffix(filePath, "/vfs_write.txt") {
		return nil, nil
	}

	return detection.Detected(), nil
}

func (d *E2eVfsWrite) Close() error {
	d.logger.Debugw("E2eVfsWrite detector closed")
	return nil
}

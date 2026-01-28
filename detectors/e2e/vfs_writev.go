//go:build e2e

package e2e

import (
	"context"
	"strings"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() { registerE2e(&E2eVfsWritev{}) }

// E2eVfsWritev is an e2e test detector for testing the vfs_writev event.
type E2eVfsWritev struct {
	logger detection.Logger
}

func (d *E2eVfsWritev) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "VFS_WRITEV",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "vfs_writev",
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "VFS_WRITEV",
			Description: "Instrumentation events E2E Tests: Vfs Writev",
			Version:     &v1beta1.Version{Major: 0, Minor: 1, Patch: 0},
			Tags:        []string{"e2e"},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *E2eVfsWritev) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Debugw("E2eVfsWritev detector initialized")
	return nil
}

func (d *E2eVfsWritev) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	filePath, err := v1beta1.GetDataSafe[string](event, "pathname")
	if err != nil {
		return nil, nil
	}

	// Check expected values from test for detection
	if !strings.HasSuffix(filePath, "/vfs_writev.txt") {
		return nil, nil
	}

	return detection.Detected(), nil
}

func (d *E2eVfsWritev) Close() error {
	d.logger.Debugw("E2eVfsWritev detector closed")
	return nil
}

//go:build e2e

package e2e

import (
	"context"
	"strings"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() { registerE2e(&E2eSecurityInodeRename{}) }

// E2eSecurityInodeRename is an e2e test detector for testing the security_inode_rename event.
type E2eSecurityInodeRename struct {
	logger detection.Logger
}

func (d *E2eSecurityInodeRename) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "SECURITY_INODE_RENAME",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "security_inode_rename",
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "SECURITY_INODE_RENAME",
			Description: "Instrumentation events E2E Tests: security_inode_rename",
			Version:     &v1beta1.Version{Major: 0, Minor: 1, Patch: 0},
			Tags:        []string{"e2e"},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *E2eSecurityInodeRename) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Debugw("E2eSecurityInodeRename detector initialized")
	return nil
}

func (d *E2eSecurityInodeRename) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	oldPath, err := v1beta1.GetDataSafe[string](event, "old_path")
	if err != nil {
		return nil, nil
	}

	newPath, err := v1beta1.GetDataSafe[string](event, "new_path")
	if err != nil {
		return nil, nil
	}

	// ATTENTION: Both, oldPath and newPath are relative to the filesystem they're in:
	// /tmp/aaa.txt comes as aaa.txt if /tmp is a tmpfs and not part of the root filesystem.
	if !strings.HasSuffix(oldPath, "aaa.txt") || !strings.HasSuffix(newPath, "bbb.txt") {
		return nil, nil
	}

	return detection.Detected(), nil
}

func (d *E2eSecurityInodeRename) Close() error {
	d.logger.Debugw("E2eSecurityInodeRename detector closed")
	return nil
}

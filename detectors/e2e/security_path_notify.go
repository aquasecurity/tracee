//go:build e2e

package e2e

import (
	"context"
	"strings"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() { registerE2e(&E2eSecurityPathNotify{}) }

// E2eSecurityPathNotify is an e2e test detector for testing the security_path_notify event.
type E2eSecurityPathNotify struct {
	logger        detection.Logger
	foundDnotify  bool
	foundInotify  bool
	foundFanotify bool
}

func (d *E2eSecurityPathNotify) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "SECURITY_PATH_NOTIFY",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "security_path_notify",
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "SECURITY_PATH_NOTIFY",
			Description: "Instrumentation events E2E Tests: Security Path Notify",
			Version:     &v1beta1.Version{Major: 0, Minor: 1, Patch: 0},
			Tags:        []string{"e2e"},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *E2eSecurityPathNotify) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.foundDnotify = false
	d.foundInotify = false
	d.foundFanotify = false
	d.logger.Debugw("E2eSecurityPathNotify detector initialized")
	return nil
}

func (d *E2eSecurityPathNotify) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	pathName, err := v1beta1.GetDataSafe[string](event, "pathname")
	if err != nil {
		return nil, nil
	}

	// Check expected values from test for detection
	if strings.HasSuffix(pathName, "/dnotify_test") {
		d.foundDnotify = true
		d.logger.Infow("found dnotify_test", "pathname", pathName)
	} else if strings.HasSuffix(pathName, "/inotify_test") {
		d.foundInotify = true
		d.logger.Infow("found inotify_test", "pathname", pathName)
	} else if strings.HasSuffix(pathName, "/fanotify_test") {
		d.foundFanotify = true
		d.logger.Infow("found fanotify_test", "pathname", pathName)
	} else {
		return nil, nil
	}

	if !d.foundDnotify || !d.foundInotify || !d.foundFanotify {
		return nil, nil
	}

	return detection.Detected(), nil
}

func (d *E2eSecurityPathNotify) Close() error {
	d.logger.Debugw("E2eSecurityPathNotify detector closed")
	return nil
}

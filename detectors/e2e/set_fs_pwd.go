//go:build e2e

package e2e

import (
	"context"
	"strings"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() { registerE2e(&E2eSetFsPwd{}) }

// E2eSetFsPwd is an e2e test detector for testing the set_fs_pwd event.
type E2eSetFsPwd struct {
	logger      detection.Logger
	hasReadUser bool
	symbolStore datastores.KernelSymbolStore
}

func (d *E2eSetFsPwd) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "SET_FS_PWD",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "set_fs_pwd",
					Dependency: detection.DependencyRequired,
				},
			},
			DataStores: []detection.DataStoreRequirement{
				{
					Name:       datastores.Symbol,
					Dependency: detection.DependencyOptional,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "SET_FS_PWD",
			Description: "Instrumentation events E2E Tests: set_fs_pwd",
			Version:     &v1beta1.Version{Major: 0, Minor: 1, Patch: 0},
			Tags:        []string{"e2e"},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *E2eSetFsPwd) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.symbolStore = params.DataStores.KernelSymbols()

	// Check if this system has the bpf_probe_read_user_str helper
	d.hasReadUser = false
	if d.symbolStore != nil {
		_, err := d.symbolStore.GetSymbolAddress("bpf_probe_read_user_str")
		d.hasReadUser = err == nil
	}

	d.logger.Debugw("E2eSetFsPwd detector initialized", "hasReadUser", d.hasReadUser)
	return nil
}

func (d *E2eSetFsPwd) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	unresolvedPath, unresolvedErr := v1beta1.GetDataSafe[string](event, "unresolved_path")
	if d.hasReadUser && unresolvedErr != nil {
		return nil, nil
	}

	resolvedPath, err := v1beta1.GetDataSafe[string](event, "resolved_path")
	if err != nil {
		return nil, nil
	}

	// Check expected values from test for detection
	if (d.hasReadUser && !strings.HasSuffix(unresolvedPath, "/test_link")) || !strings.HasSuffix(resolvedPath, "/test_dir") {
		return nil, nil
	}

	return detection.Detected(), nil
}

func (d *E2eSetFsPwd) Close() error {
	d.logger.Debugw("E2eSetFsPwd detector closed")
	return nil
}

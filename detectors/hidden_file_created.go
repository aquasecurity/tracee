package detectors

import (
	"context"
	"strings"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/elf"
)

func init() {
	register(&HiddenFileCreated{})
}

// HiddenFileCreated detects creation of hidden ELF executables.
// Adversaries may hide executables to avoid detection.
type HiddenFileCreated struct {
	logger detection.Logger
}

func (d *HiddenFileCreated) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-1015",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "magic_write",
					Dependency: detection.DependencyRequired,
					// Can't easily filter for "pathname contains /." in data filter syntax
					// and ELF detection requires byte inspection, so we handle both in OnEvent
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "hidden_file_created",
			Description: "Hidden executable (ELF file) was created on disk",
			Version: &v1beta1.Version{
				Major: 1,
				Minor: 0,
				Patch: 0,
			},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "Hidden executable creation detected",
			Description: "A hidden executable (ELF file) was created on disk. This activity could be legitimate; however, it could indicate that an adversary is trying to avoid detection by hiding their programs.",
			Severity:    v1beta1.Severity_MEDIUM,
			Mitre: &v1beta1.Mitre{
				Tactic: &v1beta1.MitreTactic{
					Name: "Defense Evasion",
				},
				Technique: &v1beta1.MitreTechnique{
					Id:   "T1564.001",
					Name: "Hidden Files and Directories",
				},
			},
			Properties: map[string]string{
				"Category": "defense-evasion",
			},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *HiddenFileCreated) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Debugw("HiddenFileCreated detector initialized")
	return nil
}

func (d *HiddenFileCreated) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Get pathname and bytes from magic_write event
	pathname, err := v1beta1.GetDataSafe[string](event, "pathname")
	if err != nil {
		return nil, nil
	}

	bytes, err := v1beta1.GetDataSafe[[]byte](event, "bytes")
	if err != nil {
		return nil, nil
	}

	// Check if this is a hidden file (contains "/.")  AND an ELF executable
	if strings.Contains(pathname, "/.") && elf.IsElf(bytes) {
		return detection.Detected(), nil
	}

	return nil, nil
}

func (d *HiddenFileCreated) Close() error {
	d.logger.Debugw("HiddenFileCreated detector closed")
	return nil
}

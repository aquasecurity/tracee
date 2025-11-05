package detectors

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/parsers"
)

func init() {
	register(&AslrInspection{})
}

// AslrInspection detects inspection of ASLR configuration.
// Adversaries may inspect ASLR settings to understand memory layout randomization
// before attempting exploitation.
type AslrInspection struct {
	logger detection.Logger
}

func (d *AslrInspection) GetDefinition() detection.DetectorDefinition {
	// Build data filter for: pathname matches ASLR config file AND flags indicate read
	// We use pathname filter directly, and IsFileRead logic requires checking O_RDONLY/O_RDWR
	// O_RDONLY=0, O_WRONLY=1, O_RDWR=2, so read operations are flags where (flags&O_WRONLY)==0 or flags==O_RDWR
	// However, simpler approach: filter for pathname and check flags in OnEvent since
	// the filter syntax might not support complex flag bit operations

	return detection.DetectorDefinition{
		ID: "TRC-109",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "security_file_open",
					Dependency: detection.DependencyRequired,
					DataFilters: []string{
						"pathname=/proc/sys/kernel/randomize_va_space",
					},
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "aslr_inspection",
			Description: "ASLR configuration was inspected",
			Version: &v1beta1.Version{
				Major: 1,
				Minor: 0,
				Patch: 0,
			},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "ASLR inspection detected",
			Description: "The ASLR (address space layout randomization) configuration was inspected. ASLR is used by Linux to prevent memory vulnerabilities. An adversary may want to inspect and change the ASLR configuration in order to avoid detection.",
			Severity:    v1beta1.Severity_INFO,
			Mitre: &v1beta1.Mitre{
				Tactic: &v1beta1.MitreTactic{
					Name: "Privilege Escalation",
				},
				Technique: &v1beta1.MitreTechnique{
					Id:   "T1068",
					Name: "Exploitation for Privilege Escalation",
				},
			},
			Properties: map[string]string{
				"Category": "privilege-escalation",
			},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *AslrInspection) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Debugw("AslrInspection detector initialized")
	return nil
}

func (d *AslrInspection) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// DataFilter ensures pathname matches, but we still need to check if this is a read operation
	flags, err := v1beta1.GetDataSafe[int64](event, "flags")
	if err != nil {
		// If flags are missing, we can't determine if this is a read - skip
		return nil, nil
	}

	// Check if this is a read operation using the same logic as the original signature
	if parsers.IsFileRead(int(flags)) {
		return []detection.DetectorOutput{{Data: nil}}, nil
	}

	// Not a read operation, no detection
	return nil, nil
}

func (d *AslrInspection) Close() error {
	d.logger.Debugw("AslrInspection detector closed")
	return nil
}

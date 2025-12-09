package detectors

import (
	"context"
	"strings"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/parsers"
)

func init() {
	register(&LdPreload{})
}

// LdPreload detects LD_PRELOAD usage (code injection technique).
// Origin: "*" (triggers on both host and containers - no container=started filter).
type LdPreload struct {
	logger      detection.Logger
	preloadEnvs []string
	preloadPath string
}

func (d *LdPreload) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-107",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "sched_process_exec",
					Dependency: detection.DependencyRequired,
					// Note: Origin "*" from original - no container filter
				},
				{
					Name:       "security_file_open",
					Dependency: detection.DependencyRequired,
					// Note: Origin "*" from original - no container filter
				},
				{
					Name:       "security_inode_rename",
					Dependency: detection.DependencyRequired,
					// Note: Origin "*" from original - no container filter
				},
			},
			Enrichments: []detection.EnrichmentRequirement{
				{
					Name:       "exec-env",
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "ld_preload",
			Description: "LD_PRELOAD code injection detected",
			Version:     &v1beta1.Version{Major: 1, Minor: 0, Patch: 0},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "LD_PRELOAD code injection detected",
			Description: "LD_PRELOAD usage was detected. LD_PRELOAD lets you load your library before any other library, allowing you to hook functions in a process. Adversaries may use this technique to change your applications' behavior or load their own programs.",
			Severity:    v1beta1.Severity_MEDIUM,
			Mitre: &v1beta1.Mitre{
				Tactic:    &v1beta1.MitreTactic{Name: "Persistence"},
				Technique: &v1beta1.MitreTechnique{Id: "T1574", Name: "Hijack Execution Flow"},
			},
			Properties: map[string]string{"Category": "persistence"},
		},
		AutoPopulate: detection.AutoPopulateFields{Threat: true, DetectedFrom: true},
	}
}

func (d *LdPreload) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.preloadEnvs = []string{"LD_PRELOAD", "LD_LIBRARY_PATH"}
	d.preloadPath = "/etc/ld.so.preload"
	d.logger.Debugw("LdPreload detector initialized")
	return nil
}

func (d *LdPreload) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	eventName := event.Name

	switch eventName {
	case "sched_process_exec":
		// Check for LD_PRELOAD or LD_LIBRARY_PATH in environment variables
		// Extract env array manually since it's a complex type
		var envVars []string
		for _, data := range event.Data {
			if data.Name == "env" {
				if strArrayVal, ok := data.Value.(*v1beta1.EventValue_StrArray); ok {
					envVars = strArrayVal.StrArray.Value
				}
				break
			}
		}

		for _, envVar := range envVars {
			for _, preloadEnv := range d.preloadEnvs {
				if strings.HasPrefix(envVar, preloadEnv+"=") {
					d.logger.Debugw("LD_PRELOAD environment variable detected", "env", envVar)
					return []detection.DetectorOutput{
						{
							Data: []*v1beta1.EventValue{
								v1beta1.NewStringValue(preloadEnv, envVar),
							},
						},
					}, nil
				}
			}
		}

	case "security_file_open":
		pathname, err := v1beta1.GetDataSafe[string](event, "pathname")
		if err != nil {
			return nil, nil
		}

		flags, err := v1beta1.GetDataSafe[int32](event, "flags")
		if err != nil {
			return nil, nil
		}

		if strings.HasSuffix(pathname, d.preloadPath) && parsers.IsFileWrite(int(flags)) {
			d.logger.Debugw("LD_PRELOAD file write detected", "path", pathname)
			return []detection.DetectorOutput{{Data: nil}}, nil
		}

	case "security_inode_rename":
		newPath, err := v1beta1.GetDataSafe[string](event, "new_path")
		if err != nil {
			return nil, nil
		}

		if strings.HasSuffix(newPath, d.preloadPath) {
			d.logger.Debugw("LD_PRELOAD file rename detected", "path", newPath)
			return []detection.DetectorOutput{{Data: nil}}, nil
		}
	}

	return nil, nil
}

func (d *LdPreload) Close() error {
	d.logger.Debugw("LdPreload detector closed")
	return nil
}

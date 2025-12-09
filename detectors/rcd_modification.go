package detectors

import (
	"context"
	"path"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/parsers"
)

func init() {
	register(&RcdModification{})
}

// RcdModification detects modifications to RC (runlevel) scripts.
// Origin: "*" (triggers on both host and containers - no container=started filter).
type RcdModification struct {
	logger     detection.Logger
	rcdCommand string
}

func (d *RcdModification) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-1026",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "security_file_open",
					Dependency: detection.DependencyRequired,
					DataFilters: []string{
						"pathname=/etc/rc.local",
						"pathname=/etc/init.d/rc.local",
						"pathname=/etc/rc1.d/*",
						"pathname=/etc/rc2.d/*",
						"pathname=/etc/rc3.d/*",
						"pathname=/etc/rc4.d/*",
						"pathname=/etc/rc5.d/*",
						"pathname=/etc/rc6.d/*",
						"pathname=/etc/rcs.d/*",
						"pathname=/etc/init.d/*",
						"pathname=/etc/rc.d/rc.local",
						"pathname=/etc/rc.d/init.d/*",
						"pathname=/etc/rc.d/*",
					},
				},
				{
					Name:       "security_inode_rename",
					Dependency: detection.DependencyRequired,
					DataFilters: []string{
						"new_path=/etc/rc.local",
						"new_path=/etc/init.d/rc.local",
						"new_path=/etc/rc1.d/*",
						"new_path=/etc/rc2.d/*",
						"new_path=/etc/rc3.d/*",
						"new_path=/etc/rc4.d/*",
						"new_path=/etc/rc5.d/*",
						"new_path=/etc/rc6.d/*",
						"new_path=/etc/rcs.d/*",
						"new_path=/etc/init.d/*",
						"new_path=/etc/rc.d/rc.local",
						"new_path=/etc/rc.d/init.d/*",
						"new_path=/etc/rc.d/*",
					},
				},
				{
					Name:       "sched_process_exec",
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "rcd_modification",
			Description: "The rcd files were modified",
			Version:     &v1beta1.Version{Major: 1, Minor: 0, Patch: 0},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "Rcd modification detected",
			Description: "The rcd files were modified. rcd files are scripts executed on boot and runlevel switch. Those scripts are responsible for service control in runlevel switch. Adversaries may add or modify rcd files in order to persist a reboot, thus maintaining malicious execution on the affected host.",
			Severity:    v1beta1.Severity_MEDIUM,
			Mitre: &v1beta1.Mitre{
				Tactic:    &v1beta1.MitreTactic{Name: "Persistence"},
				Technique: &v1beta1.MitreTechnique{Id: "T1037.004", Name: "RC Scripts"},
			},
			Properties: map[string]string{"Category": "persistence"},
		},
		AutoPopulate: detection.AutoPopulateFields{Threat: true, DetectedFrom: true},
	}
}

func (d *RcdModification) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.rcdCommand = "update-rc.d"
	d.logger.Debugw("RcdModification detector initialized")
	return nil
}

func (d *RcdModification) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	eventName := event.Name

	switch eventName {
	case "security_file_open":
		flags, err := v1beta1.GetDataSafe[int32](event, "flags")
		if err != nil {
			return nil, nil
		}

		if !parsers.IsFileWrite(int(flags)) {
			return nil, nil
		}

		// DataFilter already validated pathname is an rcd file
		pathname, _ := v1beta1.GetDataSafe[string](event, "pathname")
		d.logger.Debugw("Rcd file modification detected", "path", pathname)
		return detection.Detected(), nil

	case "security_inode_rename":
		// DataFilter already validated new_path is an rcd file
		newPath, _ := v1beta1.GetDataSafe[string](event, "new_path")
		d.logger.Debugw("Rcd file rename detected", "path", newPath)
		return detection.Detected(), nil

	case "sched_process_exec":
		pathname := v1beta1.GetProcessExecutablePath(event)
		basename := path.Base(pathname)
		if basename == d.rcdCommand {
			d.logger.Debugw("Rcd command execution detected", "command", basename)
			return detection.Detected(), nil
		}
	}

	return nil, nil
}

func (d *RcdModification) Close() error {
	d.logger.Debugw("RcdModification detector closed")
	return nil
}

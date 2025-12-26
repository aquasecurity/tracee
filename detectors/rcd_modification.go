package detectors

import (
	"context"
	"path"
	"strings"

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
	rcdFiles   map[string]bool
	rcdDirs    []string
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
				},
				{
					Name:       "security_inode_rename",
					Dependency: detection.DependencyRequired,
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
	d.rcdFiles = map[string]bool{
		"/etc/rc.local":        true,
		"/etc/init.d/rc.local": true,
	}
	d.rcdDirs = []string{
		"/etc/rc1.d", "/etc/rc2.d", "/etc/rc3.d", "/etc/rc4.d", "/etc/rc5.d", "/etc/rc6.d",
		"/etc/rcs.d", "/etc/init.d", "/etc/rc.d/rc.local", "/etc/rc.d/init.d", "/etc/rc.d",
	}
	d.rcdCommand = "update-rc.d"
	d.logger.Debugw("RcdModification detector initialized")
	return nil
}

func (d *RcdModification) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	eventName := event.Name

	switch eventName {
	case "security_file_open":
		pathname, err := v1beta1.GetDataSafe[string](event, "pathname")
		if err != nil {
			return nil, nil
		}

		// Check if it's a write operation (matching original signature logic)
		flags, err := v1beta1.GetDataSafe[int32](event, "flags")
		if err != nil {
			return nil, nil
		}

		if !parsers.IsFileWrite(int(flags)) {
			return nil, nil
		}

		if d.checkFileOrDir(pathname) {
			d.logger.Debugw("Rcd file modification detected", "path", pathname)
			return []detection.DetectorOutput{{Data: nil}}, nil
		}
	case "security_inode_rename":
		newPath, err := v1beta1.GetDataSafe[string](event, "new_path")
		if err != nil {
			return nil, nil
		}
		if d.checkFileOrDir(newPath) {
			d.logger.Debugw("Rcd file rename detected", "path", newPath)
			return []detection.DetectorOutput{{Data: nil}}, nil
		}
	case "sched_process_exec":
		pathname := v1beta1.GetProcessExecutablePath(event)
		basename := path.Base(pathname)
		if basename == d.rcdCommand {
			d.logger.Debugw("Rcd command execution detected", "command", basename)
			return []detection.DetectorOutput{{Data: nil}}, nil
		}
	}

	return nil, nil
}

func (d *RcdModification) checkFileOrDir(pathname string) bool {
	// Check if path matches rcd files
	if d.rcdFiles[pathname] {
		return true
	}

	// Check if path is within rcd directories
	for _, dir := range d.rcdDirs {
		if strings.HasPrefix(pathname, dir) {
			return true
		}
	}

	return false
}

func (d *RcdModification) Close() error {
	d.logger.Debugw("RcdModification detector closed")
	return nil
}

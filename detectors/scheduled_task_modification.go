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
	register(&ScheduledTaskModification{})
}

// ScheduledTaskModification detects modifications to cron/scheduled task files.
// Origin: "*" (triggers on both host and containers - no container=started filter).
type ScheduledTaskModification struct {
	logger       detection.Logger
	cronFiles    map[string]bool
	cronDirs     []string
	cronCommands map[string]bool
}

func (d *ScheduledTaskModification) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-1027",
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
			Name:        "scheduled_task_mod",
			Description: "The task scheduling functionality or files were modified",
			Version:     &v1beta1.Version{Major: 1, Minor: 0, Patch: 0},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "Scheduled tasks modification detected",
			Description: "The task scheduling functionality or files were modified. Crontab schedules task execution or enables task execution at boot time. Adversaries may add or modify scheduled tasks in order to persist a reboot, thus maintaining malicious execution on the affected host.",
			Severity:    v1beta1.Severity_MEDIUM,
			Mitre: &v1beta1.Mitre{
				Tactic:    &v1beta1.MitreTactic{Name: "Persistence"},
				Technique: &v1beta1.MitreTechnique{Id: "T1053.003", Name: "Cron"},
			},
			Properties: map[string]string{"Category": "persistence"},
		},
		AutoPopulate: detection.AutoPopulateFields{Threat: true, DetectedFrom: true},
	}
}

func (d *ScheduledTaskModification) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.cronFiles = map[string]bool{
		"/etc/crontab":    true,
		"/etc/anacrontab": true,
		"/etc/cron.deny":  true,
		"/etc/cron.allow": true,
	}
	d.cronDirs = []string{
		"/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly",
		"/etc/cron.monthly", "/etc/cron.d", "/var/spool/cron/crontabs", "var/spool/anacron",
	}
	d.cronCommands = map[string]bool{
		"crontab": true,
		"at":      true,
		"batch":   true,
		"launchd": true,
	}
	d.logger.Debugw("ScheduledTaskModification detector initialized")
	return nil
}

func (d *ScheduledTaskModification) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
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
			d.logger.Debugw("Scheduled task file modification detected", "path", pathname)
			return []detection.DetectorOutput{{Data: nil}}, nil
		}
	case "security_inode_rename":
		newPath, err := v1beta1.GetDataSafe[string](event, "new_path")
		if err != nil {
			return nil, nil
		}
		if d.checkFileOrDir(newPath) {
			d.logger.Debugw("Scheduled task file rename detected", "path", newPath)
			return []detection.DetectorOutput{{Data: nil}}, nil
		}
	case "sched_process_exec":
		pathname := v1beta1.GetProcessExecutablePath(event)
		basename := path.Base(pathname)
		if d.cronCommands[basename] {
			d.logger.Debugw("Scheduled task command execution detected", "command", basename)
			return []detection.DetectorOutput{{Data: nil}}, nil
		}
	}

	return nil, nil
}

func (d *ScheduledTaskModification) checkFileOrDir(pathname string) bool {
	// Check if path matches cron files
	if d.cronFiles[pathname] {
		return true
	}

	// Check if path is within cron directories
	for _, dir := range d.cronDirs {
		if strings.HasPrefix(pathname, dir) {
			return true
		}
	}

	return false
}

func (d *ScheduledTaskModification) Close() error {
	d.logger.Debugw("ScheduledTaskModification detector closed")
	return nil
}

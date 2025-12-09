package detectors

import (
	"context"
	"path"

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
					DataFilters: []string{
						"pathname=/etc/crontab",
						"pathname=/etc/anacrontab",
						"pathname=/etc/cron.deny",
						"pathname=/etc/cron.allow",
						"pathname=/etc/cron.hourly/*",
						"pathname=/etc/cron.daily/*",
						"pathname=/etc/cron.weekly/*",
						"pathname=/etc/cron.monthly/*",
						"pathname=/etc/cron.d/*",
						"pathname=/var/spool/cron/crontabs/*",
						"pathname=var/spool/anacron/*",
					},
				},
				{
					Name:       "security_inode_rename",
					Dependency: detection.DependencyRequired,
					DataFilters: []string{
						"new_path=/etc/crontab",
						"new_path=/etc/anacrontab",
						"new_path=/etc/cron.deny",
						"new_path=/etc/cron.allow",
						"new_path=/etc/cron.hourly/*",
						"new_path=/etc/cron.daily/*",
						"new_path=/etc/cron.weekly/*",
						"new_path=/etc/cron.monthly/*",
						"new_path=/etc/cron.d/*",
						"new_path=/var/spool/cron/crontabs/*",
						"new_path=var/spool/anacron/*",
					},
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
		flags, err := v1beta1.GetDataSafe[int32](event, "flags")
		if err != nil {
			return nil, nil
		}

		if !parsers.IsFileWrite(int(flags)) {
			return nil, nil
		}

		// DataFilter already validated pathname is a cron file
		pathname, _ := v1beta1.GetDataSafe[string](event, "pathname")
		d.logger.Debugw("Scheduled task file modification detected", "path", pathname)
		return detection.Detected(), nil

	case "security_inode_rename":
		// DataFilter already validated new_path is a cron file
		newPath, _ := v1beta1.GetDataSafe[string](event, "new_path")
		d.logger.Debugw("Scheduled task file rename detected", "path", newPath)
		return detection.Detected(), nil

	case "sched_process_exec":
		pathname := v1beta1.GetProcessExecutablePath(event)
		basename := path.Base(pathname)
		if d.cronCommands[basename] {
			d.logger.Debugw("Scheduled task command execution detected", "command", basename)
			return detection.Detected(), nil
		}
	}

	return nil, nil
}

func (d *ScheduledTaskModification) Close() error {
	d.logger.Debugw("ScheduledTaskModification detector closed")
	return nil
}

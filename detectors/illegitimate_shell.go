package detectors

import (
	"context"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() {
	register(&IllegitimateShell{})
}

// IllegitimateShell detects when a web server spawns a shell process.
// This indicates potential exploitation of the web server for command execution.
type IllegitimateShell struct {
	logger                 detection.Logger
	shellNames             map[string]bool
	webServersProcessNames map[string]bool
}

func (d *IllegitimateShell) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-1016",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "sched_process_exec",
					Dependency: detection.DependencyRequired,
					// No DataFilters - we need to check both process name and parent name
					// which requires runtime logic
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "illegitimate_shell",
			Description: "Web server spawned a shell",
			Version: &v1beta1.Version{
				Major: 1,
				Minor: 0,
				Patch: 0,
			},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "Web server spawned a shell",
			Description: "A web-server program on your server spawned a shell program. Shell is the linux command-line program, web servers usually don't run shell programs, so this alert might indicate an adversary is exploiting a web server program to gain command execution on the server.",
			Severity:    v1beta1.Severity_MEDIUM,
			Mitre: &v1beta1.Mitre{
				Tactic: &v1beta1.MitreTactic{
					Name: "Initial Access",
				},
				Technique: &v1beta1.MitreTechnique{
					Id:   "T1190",
					Name: "Exploit Public-Facing Application",
				},
			},
			Properties: map[string]string{
				"Category": "initial-access",
			},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:       true,
			DetectedFrom: true,
		},
	}
}

func (d *IllegitimateShell) Init(params detection.DetectorParams) error {
	d.logger = params.Logger

	// Initialize shell names set
	d.shellNames = map[string]bool{
		"ash":  true,
		"bash": true,
		"csh":  true,
		"ksh":  true,
		"sh":   true,
		"tcsh": true,
		"zsh":  true,
		"dash": true,
	}

	// Initialize web server process names set
	d.webServersProcessNames = map[string]bool{
		"nginx":           true,
		"httpd":           true,
		"httpd-foregroun": true,
		"http-nio":        true,
		"lighttpd":        true,
		"apache":          true,
		"apache2":         true,
	}

	d.logger.Debugw("IllegitimateShell detector initialized")
	return nil
}

func (d *IllegitimateShell) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Extract process name (comm/thread name)
	processName := v1beta1.GetProcessThreadName(event)
	if processName == "" {
		return nil, nil
	}

	// Check if current process is a shell
	if !d.shellNames[processName] {
		return nil, nil
	}

	// Extract parent process name
	prevComm, err := v1beta1.GetDataSafe[string](event, "prev_comm")
	if err != nil {
		d.logger.Debugw("Failed to extract prev_comm", "error", err)
		return nil, nil
	}

	// Check if parent process is a web server
	if !d.webServersProcessNames[prevComm] {
		return nil, nil
	}

	// Detection: web server spawned a shell
	d.logger.Debugw("Web server spawned shell",
		"webserver", prevComm,
		"shell", processName)

	return detection.Detected(), nil
}

func (d *IllegitimateShell) Close() error {
	d.logger.Debugw("IllegitimateShell detector closed")
	return nil
}

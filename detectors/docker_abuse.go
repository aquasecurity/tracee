package detectors

import (
	"context"
	"strings"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/parsers"
)

func init() {
	register(&DockerAbuse{})
}

// DockerAbuse detects attempts to abuse the Docker socket from within a container.
// Origin: "container" -> Uses ScopeFilters: container=started (CRITICAL for parity).
type DockerAbuse struct {
	logger     detection.Logger
	dockerSock string
}

func (d *DockerAbuse) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-1019",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:         "security_file_open",
					Dependency:   detection.DependencyRequired,
					ScopeFilters: []string{"container=started"},
					DataFilters: []string{
						"pathname=*docker.sock",
					},
				},
				{
					Name:         "security_socket_connect",
					Dependency:   detection.DependencyRequired,
					ScopeFilters: []string{"container=started"},
					// Note: Cannot use DataFilter - path is in nested sockaddr.SunPath structure
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "docker_abuse",
			Description: "Docker socket abuse detected",
			Version:     &v1beta1.Version{Major: 1, Minor: 0, Patch: 0},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "Docker socket abuse detected",
			Description: "An attempt to abuse the Docker UNIX socket inside a container was detected. docker.sock is the UNIX socket that Docker uses as the entry point to the Docker API. Adversaries may attempt to abuse this socket to compromise the system.",
			Severity:    v1beta1.Severity_MEDIUM,
			Mitre: &v1beta1.Mitre{
				Tactic:    &v1beta1.MitreTactic{Name: "Privilege Escalation"},
				Technique: &v1beta1.MitreTechnique{Id: "T1068", Name: "Exploitation for Privilege Escalation"},
			},
			Properties: map[string]string{"Category": "privilege-escalation"},
		},
		AutoPopulate: detection.AutoPopulateFields{Threat: true, DetectedFrom: true},
	}
}

func (d *DockerAbuse) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.dockerSock = "docker.sock"
	d.logger.Debugw("DockerAbuse detector initialized")
	return nil
}

func (d *DockerAbuse) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
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

		// DataFilter already validated pathname ends with docker.sock
		pathname, _ := v1beta1.GetDataSafe[string](event, "pathname")
		d.logger.Debugw("Docker socket abuse detected", "path", pathname)
		return detection.Detected(), nil

	case "security_socket_connect":
		// Get sockaddr which contains the socket address
		var path string
		for _, data := range event.Data {
			if data.Name == "remote_addr" {
				if sockAddrVal, ok := data.Value.(*v1beta1.EventValue_Sockaddr); ok {
					sockAddr := sockAddrVal.Sockaddr
					if sockAddr == nil {
						return nil, nil
					}
					// Check if it's a Unix socket
					if sockAddr.SaFamily == v1beta1.SaFamilyT_AF_UNIX {
						path = sockAddr.SunPath
					}
				}
				break
			}
		}

		// Manual check needed - cannot use DataFilter for nested sockaddr structure
		if strings.HasSuffix(path, d.dockerSock) {
			d.logger.Debugw("Docker socket abuse detected", "path", path)
			return detection.Detected(), nil
		}
	}

	return nil, nil
}

func (d *DockerAbuse) Close() error {
	d.logger.Debugw("DockerAbuse detector closed")
	return nil
}

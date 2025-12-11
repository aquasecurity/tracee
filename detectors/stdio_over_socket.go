package detectors

import (
	"context"
	"fmt"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() {
	register(&StdioOverSocket{})
}

// StdioOverSocket detects reverse shell attacks (stdio redirected to socket).
// Origin: "*" (triggers on both host and containers - no container=started filter).
type StdioOverSocket struct {
	logger     detection.Logger
	legitPorts map[string]bool
}

func (d *StdioOverSocket) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-101",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "security_socket_connect",
					Dependency: detection.DependencyRequired,
					// Note: Origin "*" from original - no container filter
				},
				{
					Name:       "socket_dup",
					Dependency: detection.DependencyRequired,
					// Note: Origin "*" from original - no container filter
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "stdio_over_socket",
			Description: "Process standard input/output over socket detected",
			Version:     &v1beta1.Version{Major: 2, Minor: 0, Patch: 0},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "Process standard input/output over socket detected",
			Description: "A process has its standard input/output redirected to a socket. This behavior is the base of a Reverse Shell attack, which is when an interactive shell being invoked from a target machine back to the attacker's machine, giving it interactive control over the target. Adversaries may use a Reverse Shell to retain control over a compromised target while bypassing security measures like network firewalls.",
			Severity:    v1beta1.Severity_HIGH,
			Mitre: &v1beta1.Mitre{
				Tactic:    &v1beta1.MitreTactic{Name: "Execution"},
				Technique: &v1beta1.MitreTechnique{Id: "T1059.004", Name: "Unix Shell"},
			},
			Properties: map[string]string{"Category": "execution"},
		},
		AutoPopulate: detection.AutoPopulateFields{Threat: true, DetectedFrom: true},
	}
}

func (d *StdioOverSocket) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.legitPorts = map[string]bool{
		"":  true, // Empty port
		"0": true, // Port 0
	}
	d.logger.Debugw("StdioOverSocket detector initialized")
	return nil
}

func (d *StdioOverSocket) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	eventName := event.Name
	var sockfd int32

	switch eventName {
	case "security_socket_connect":
		fd, err := v1beta1.GetDataSafe[int32](event, "sockfd")
		if err != nil {
			return nil, nil
		}
		sockfd = fd
	case "socket_dup":
		fd, err := v1beta1.GetDataSafe[int32](event, "newfd")
		if err != nil {
			return nil, nil
		}
		sockfd = fd
	default:
		return nil, nil
	}

	// Check if sockfd is stdin (0), stdout (1), or stderr (2)
	if sockfd != 0 && sockfd != 1 && sockfd != 2 {
		return nil, nil
	}

	// Extract socket address to get IP and port
	for _, data := range event.Data {
		if data.Name == "remote_addr" {
			if sockAddrVal, ok := data.Value.(*v1beta1.EventValue_Sockaddr); ok {
				sockAddr := sockAddrVal.Sockaddr
				if sockAddr == nil {
					return nil, nil
				}
				// Check for internet family connections (IPv4 or IPv6)
				if sockAddr.SaFamily != v1beta1.SaFamilyT_AF_INET && sockAddr.SaFamily != v1beta1.SaFamilyT_AF_INET6 {
					return nil, nil
				}

				var ip string
				var port string

				if sockAddr.SaFamily == v1beta1.SaFamilyT_AF_INET {
					ip = sockAddr.SinAddr
					port = fmt.Sprintf("%d", sockAddr.SinPort)
				} else {
					ip = sockAddr.Sin6Addr
					port = fmt.Sprintf("%d", sockAddr.Sin6Port)
				}

				// Check if port is in the allowlist
				if d.legitPorts[port] {
					return nil, nil
				}

				d.logger.Debugw("Reverse shell detected", "ip", ip, "port", port, "fd", sockfd)
				return []detection.DetectorOutput{
					{
						Data: []*v1beta1.EventValue{
							v1beta1.NewStringValue("IP address", ip),
							v1beta1.NewStringValue("Port", port),
							v1beta1.NewInt32Value("File descriptor", sockfd),
						},
					},
				}, nil
			}
			break
		}
	}

	return nil, nil
}

func (d *StdioOverSocket) Close() error {
	d.logger.Debugw("StdioOverSocket detector closed")
	return nil
}

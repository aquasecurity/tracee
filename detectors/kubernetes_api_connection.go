package detectors

import (
	"context"
	"strings"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

func init() {
	register(&KubernetesApiConnection{})
}

// KubernetesApiConnection detects connections to the Kubernetes API server.
// Origin: "container" -> Uses ScopeFilters: container=started (CRITICAL for parity).
// Requires: exec-env enrichment to read KUBERNETES_SERVICE_HOST environment variable.
type KubernetesApiConnection struct {
	logger                detection.Logger
	apiAddressContainerId map[string]string
}

func (d *KubernetesApiConnection) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-1013",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:         "sched_process_exec",
					Dependency:   detection.DependencyRequired,
					ScopeFilters: []string{"container=started"}, // CRITICAL: container=started for parity
				},
				{
					Name:         "security_socket_connect",
					Dependency:   detection.DependencyRequired,
					ScopeFilters: []string{"container=started"}, // CRITICAL: container=started for parity
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
			Name:        "k8s_api_connection",
			Description: "Kubernetes API server connection detected",
			Version:     &v1beta1.Version{Major: 0, Minor: 1, Patch: 0},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "Kubernetes API server connection detected",
			Description: "A connection to the kubernetes API server was detected. The K8S API server is the brain of your K8S cluster, adversaries may try and communicate with the K8S API server to gather information/credentials, or even run more containers and laterally expand their grip on your systems.",
			Severity:    v1beta1.Severity_LOW,
			Mitre: &v1beta1.Mitre{
				Tactic:    &v1beta1.MitreTactic{Name: "Discovery"},
				Technique: &v1beta1.MitreTechnique{Name: "Cloud Service Discovery"},
			},
			Properties: map[string]string{
				"Category":     "discovery",
				"MITRE ATT&CK": "Discovery: Cloud Service Discovery",
			},
		},
		AutoPopulate: detection.AutoPopulateFields{Threat: true, DetectedFrom: true},
	}
}

func (d *KubernetesApiConnection) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.apiAddressContainerId = make(map[string]string)
	d.logger.Debugw("KubernetesApiConnection detector initialized")
	return nil
}

func (d *KubernetesApiConnection) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	eventName := event.Name
	containerID := ""
	if event.Workload != nil && event.Workload.Container != nil {
		containerID = event.Workload.Container.Id
	}

	if containerID == "" {
		return nil, nil
	}

	switch eventName {
	case "sched_process_exec":
		// Extract environment variables to find KUBERNETES_SERVICE_HOST
		var envVars []string
		for _, data := range event.Data {
			if data.Name == "env" {
				if strArrayVal, ok := data.Value.(*v1beta1.EventValue_StrArray); ok {
					envVars = strArrayVal.StrArray.Value
				}
				break
			}
		}

		apiIPAddress := getApiAddressFromEnvs(envVars)
		if apiIPAddress != "" {
			d.apiAddressContainerId[containerID] = apiIPAddress
			d.logger.Debugw("Kubernetes API address cached", "container", containerID, "api_ip", apiIPAddress)
		}

	case "security_socket_connect":
		apiAddress, exists := d.apiAddressContainerId[containerID]
		if !exists {
			return nil, nil
		}

		// Extract sockaddr to get the IP being connected to
		for _, data := range event.Data {
			if data.Name == "remote_addr" {
				if sockAddrVal, ok := data.Value.(*v1beta1.EventValue_Sockaddr); ok {
					sockAddr := sockAddrVal.Sockaddr
					if sockAddr == nil {
						return nil, nil
					}
					// Check for internet family connections
					if sockAddr.SaFamily == v1beta1.SaFamilyT_AF_INET || sockAddr.SaFamily == v1beta1.SaFamilyT_AF_INET6 {
						var ip string
						if sockAddr.SaFamily == v1beta1.SaFamilyT_AF_INET {
							ip = sockAddr.SinAddr
						} else {
							ip = sockAddr.Sin6Addr
						}

						if ip == apiAddress {
							d.logger.Debugw("Kubernetes API connection detected", "container", containerID, "api_ip", apiAddress)
							return []detection.DetectorOutput{
								{
									Data: []*v1beta1.EventValue{
										v1beta1.NewStringValue("ip", apiAddress),
									},
								},
							}, nil
						}
					}
				}
				break
			}
		}
	}

	return nil, nil
}

func (d *KubernetesApiConnection) Close() error {
	d.logger.Debugw("KubernetesApiConnection detector closed")
	return nil
}

// getApiAddressFromEnvs extracts the Kubernetes API server IP from environment variables
func getApiAddressFromEnvs(envs []string) string {
	for _, env := range envs {
		if strings.Contains(env, "KUBERNETES_SERVICE_HOST=") {
			i := strings.Index(env, "=")
			return strings.TrimSpace(env[i+1:])
		}
	}
	return ""
}

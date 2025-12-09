package detectors

import (
	"context"
	"path/filepath"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/parsers"
)

func init() {
	register(&KubernetesCertificateTheft{})
}

// KubernetesCertificateTheft detects attempts to read Kubernetes TLS certificates.
// Origin: "*" (triggers on both host and containers - no container=started filter).
type KubernetesCertificateTheft struct {
	logger     detection.Logger
	legitProcs map[string]bool
}

func (d *KubernetesCertificateTheft) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-1018",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "security_file_open",
					Dependency: detection.DependencyRequired,
					DataFilters: []string{
						"pathname=/etc/kubernetes/pki/*",
					},
				},
				{
					Name:       "security_inode_rename",
					Dependency: detection.DependencyRequired,
					DataFilters: []string{
						"old_path=/etc/kubernetes/pki/*",
					},
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "k8s_cert_theft",
			Description: "Theft of Kubernetes TLS certificates was detected",
			Version:     &v1beta1.Version{Major: 1, Minor: 0, Patch: 0},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "K8s TLS certificate theft detected",
			Description: "Theft of Kubernetes TLS certificates was detected. TLS certificates are used to establish trust between systems. The Kubernetes certificate is used to to enable secure communication between Kubernetes components, such as kubelet scheduler controller and API Server. An adversary may steal a Kubernetes certificate on a compromised system to impersonate Kubernetes components within the cluster.",
			Severity:    v1beta1.Severity_HIGH,
			Mitre: &v1beta1.Mitre{
				Tactic:    &v1beta1.MitreTactic{Name: "Credential Access"},
				Technique: &v1beta1.MitreTechnique{Id: "T1528", Name: "Steal Application Access Token"},
			},
			Properties: map[string]string{"Category": "credential-access"},
		},
		AutoPopulate: detection.AutoPopulateFields{Threat: true, DetectedFrom: true},
	}
}

func (d *KubernetesCertificateTheft) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.legitProcs = map[string]bool{
		"kube-apiserver":  true,
		"kubelet":         true,
		"kube-controller": true,
		"etcd":            true,
	}
	d.logger.Debugw("KubernetesCertificateTheft detector initialized")
	return nil
}

func (d *KubernetesCertificateTheft) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	eventName := event.Name

	switch eventName {
	case "security_file_open":
		// Check if process is on allowlist
		execPath := v1beta1.GetProcessExecutablePath(event)
		processName := filepath.Base(execPath)
		if d.legitProcs[processName] {
			return nil, nil
		}

		flags, err := v1beta1.GetDataSafe[int32](event, "flags")
		if err != nil {
			return nil, nil
		}

		if !parsers.IsFileRead(int(flags)) {
			return nil, nil
		}

	case "security_inode_rename":
		// DataFilter already validated old_path, just detect
	default:
		return nil, nil
	}

	// DataFilter already validated path is under /etc/kubernetes/pki/
	pathname, _ := v1beta1.GetDataSafe[string](event, "pathname")
	if pathname == "" {
		pathname, _ = v1beta1.GetDataSafe[string](event, "old_path")
	}

	d.logger.Debugw("Kubernetes certificate access detected", "path", pathname)
	return detection.Detected(), nil
}

func (d *KubernetesCertificateTheft) Close() error {
	d.logger.Debugw("KubernetesCertificateTheft detector closed")
	return nil
}

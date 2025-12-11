package detectors

import (
	"context"
	"path/filepath"
	"regexp"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/parsers"
)

func init() {
	register(&K8SServiceAccountToken{})
}

// K8SServiceAccountToken detects reads of Kubernetes service account token files.
// Adversaries may try to steal these tokens to communicate with the API Server.
type K8SServiceAccountToken struct {
	logger        detection.Logger
	legitProcs    map[string]bool
	compiledRegex *regexp.Regexp
}

var tokenPathRegexString = `secrets/kubernetes\.io/serviceaccount/.*token$`

func (d *K8SServiceAccountToken) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-108",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:         "security_file_open",
					Dependency:   detection.DependencyRequired,
					ScopeFilters: []string{"container=started"},
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "k8s_service_account_token",
			Description: "K8s service account token file read",
			Version:     &v1beta1.Version{Major: 1, Minor: 0, Patch: 0},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "K8s service account token file read",
			Description: "The Kubernetes service account token file was read on your container. This token is used to communicate with the Kubernetes API Server. Adversaries may try to communicate with the API Server to steal information and/or credentials, or even run more containers and laterally extend their grip on the systems.",
			Severity:    v1beta1.Severity_INFO,
			Mitre: &v1beta1.Mitre{
				Tactic:    &v1beta1.MitreTactic{Name: "Credential Access"},
				Technique: &v1beta1.MitreTechnique{Id: "T1212", Name: "Exploitation for Credential Access"},
			},
			Properties: map[string]string{"Category": "credential-access", "Kubernetes_Technique": "Container service account"},
		},
		AutoPopulate: detection.AutoPopulateFields{Threat: true, DetectedFrom: true},
	}
}

func (d *K8SServiceAccountToken) Init(params detection.DetectorParams) error {
	var err error
	d.logger = params.Logger
	d.legitProcs = map[string]bool{
		"flanneld":        true,
		"kube-proxy":      true,
		"etcd":            true,
		"kube-apiserver":  true,
		"coredns":         true,
		"kube-controller": true,
		"kubectl":         true,
	}
	d.compiledRegex, err = regexp.Compile(tokenPathRegexString)
	if err != nil {
		return err
	}
	d.logger.Debugw("K8SServiceAccountToken detector initialized")
	return nil
}

func (d *K8SServiceAccountToken) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
	// Check if process is on allow list
	execPath := v1beta1.GetProcessExecutablePath(event)
	processName := filepath.Base(execPath)
	if d.legitProcs[processName] {
		return nil, nil
	}

	pathname, err := v1beta1.GetDataSafe[string](event, "pathname")
	if err != nil {
		return nil, nil
	}

	flags, err := v1beta1.GetDataSafe[int32](event, "flags")
	if err != nil {
		return nil, nil
	}

	if parsers.IsFileRead(int(flags)) && d.compiledRegex.MatchString(pathname) {
		d.logger.Debugw("K8s service account token read", "path", pathname, "process", processName)
		return []detection.DetectorOutput{{Data: nil}}, nil
	}

	return nil, nil
}

func (d *K8SServiceAccountToken) Close() error {
	d.logger.Debugw("K8SServiceAccountToken detector closed")
	return nil
}

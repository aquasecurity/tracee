package main

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type KubernetesCertificateTheftAttempt struct {
	cb                 detect.SignatureHandler
	legitProcs         []string
	k8sCertificatesDir string
}

func (sig *KubernetesCertificateTheftAttempt) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	sig.legitProcs = []string{"kube-apiserver", "kubelet", "kube-controller", "etcd"}
	sig.k8sCertificatesDir = "/etc/kubernetes/pki/"
	return nil
}

func (sig *KubernetesCertificateTheftAttempt) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "TRC-1018",
		Version:     "1",
		Name:        "K8s TLS certificate theft detected",
		EventName:   "k8s_cert_theft",
		Description: "Theft of Kubernetes TLS certificates was detected. TLS certificates are used to establish trust between systems. The Kubernetes certificate is used to to enable secure communication between Kubernetes components, such as kubelet scheduler controller and API Server. An adversary may steal a Kubernetes certificate on a compromised system to impersonate Kubernetes components within the cluster.",
		Properties: map[string]interface{}{
			"Severity":             3,
			"Category":             "credential-access",
			"Technique":            "Steal Application Access Token",
			"Kubernetes_Technique": "",
			"id":                   "attack-pattern--890c9858-598c-401d-a4d5-c67ebcdd703a",
			"external_id":          "T1528",
		},
	}, nil
}

func (sig *KubernetesCertificateTheftAttempt) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "security_file_open", Origin: "*"},
		{Source: "tracee", Name: "security_inode_rename", Origin: "*"},
	}, nil
}

func (sig *KubernetesCertificateTheftAttempt) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("invalid event")
	}

	path := ""

	switch eventObj.EventName {
	case "security_file_open":
		// check process touching certificate is not on allow list
		for _, legitProc := range sig.legitProcs {
			if legitProc == eventObj.ProcessName {
				return nil
			}
		}

		flags, err := helpers.GetTraceeIntArgumentByName(eventObj, "flags")
		if err != nil {
			return err
		}

		if helpers.IsFileRead(flags) {
			pathname, err := helpers.GetTraceeStringArgumentByName(eventObj, "pathname")
			if err != nil {
				return err
			}

			path = pathname
		}
	case "security_inode_rename":
		oldPath, err := helpers.GetTraceeStringArgumentByName(eventObj, "old_path")
		if err != nil {
			return err
		}

		path = oldPath
	}

	if strings.HasPrefix(path, sig.k8sCertificatesDir) {
		metadata, err := sig.GetMetadata()
		if err != nil {
			return err
		}
		sig.cb(&detect.Finding{
			SigMetadata: metadata,
			Event:       event,
			Data:        nil,
		})
	}

	return nil
}

func (sig *KubernetesCertificateTheftAttempt) OnSignal(s detect.Signal) error {
	return nil
}
func (sig *KubernetesCertificateTheftAttempt) Close() {}

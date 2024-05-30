package main

import (
	"fmt"
	"regexp"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type K8SServiceAccountToken struct {
	cb               detect.SignatureHandler
	legitProcs       []string
	tokenPathPattern string
	compiledRegex    *regexp.Regexp
}

func (sig *K8SServiceAccountToken) Init(ctx detect.SignatureContext) error {
	var err error
	sig.cb = ctx.Callback
	sig.legitProcs = []string{"flanneld", "kube-proxy", "etcd", "kube-apiserver", "coredns", "kube-controller", "kubectl"}
	sig.tokenPathPattern = `secrets/kubernetes.io/serviceaccount.+token$`
	sig.compiledRegex, err = regexp.Compile(sig.tokenPathPattern)
	return err
}

func (sig *K8SServiceAccountToken) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "TRC-108",
		Version:     "1",
		Name:        "K8s service account token file read",
		EventName:   "k8s_service_account_token",
		Description: "The Kubernetes service account token file was read on your container. This token is used to communicate with the Kubernetes API Server. Adversaries may try to communicate with the API Server to steal information and/or credentials, or even run more containers and laterally extend their grip on the systems.",
		Properties: map[string]interface{}{
			"Severity":             0,
			"Category":             "credential-access",
			"Technique":            "Exploitation for Credential Access",
			"Kubernetes_Technique": "Container service account",
			"id":                   "attack-pattern--9c306d8d-cde7-4b4c-b6e8-d0bb16caca36",
			"external_id":          "T1212",
		},
	}, nil
}

func (sig *K8SServiceAccountToken) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "security_file_open", Origin: "container"},
	}, nil
}

func (sig *K8SServiceAccountToken) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("invalid event")
	}

	switch eventObj.EventName {
	case "security_file_open":
		// check process touching token is not on allow list
		for _, legitProc := range sig.legitProcs {
			if legitProc == eventObj.ProcessName {
				return nil
			}
		}

		pathname, err := helpers.GetTraceeStringArgumentByName(eventObj, "pathname")
		if err != nil {
			return err
		}

		flags, err := helpers.GetTraceeIntArgumentByName(eventObj, "flags")
		if err != nil {
			return err
		}

		if helpers.IsFileRead(flags) && sig.compiledRegex.MatchString(pathname) {
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
	}

	return nil
}

func (sig *K8SServiceAccountToken) OnSignal(s detect.Signal) error {
	return nil
}
func (sig *K8SServiceAccountToken) Close() {}

package main

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type K8sApiConnection struct {
	cb                    detect.SignatureHandler
	apiAddressContainerId map[string]string
}

var k8sApiConnectionMetadata = detect.SignatureMetadata{
	ID:          "TRC-1013",
	Version:     "0.1.0",
	Name:        "Kubernetes API server connection detected",
	EventName:   "k8s_api_connection",
	Description: "A connection to the kubernetes API server was detected. The K8S API server is the brain of your K8S cluster, adversaries may try and communicate with the K8S API server to gather information/credentials, or even run more containers and laterally expand their grip on your systems.",
	Tags:        []string{"container"},
	Properties: map[string]interface{}{
		"Severity":     1,
		"MITRE ATT&CK": "Discovery: Cloud Service Discovery",
	},
}

func (sig *K8sApiConnection) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	sig.apiAddressContainerId = make(map[string]string)

	return nil
}

func (sig *K8sApiConnection) GetMetadata() (detect.SignatureMetadata, error) {
	return k8sApiConnectionMetadata, nil
}

func (sig *K8sApiConnection) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "sched_process_exec", Origin: "container"},
		{Source: "tracee", Name: "security_socket_connect", Origin: "container"},
	}, nil
}

func (sig *K8sApiConnection) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}

	containerID := eventObj.Container.ID
	if containerID == "" {
		return nil
	}

	switch eventObj.EventName {
	case "sched_process_exec":
		envVars, err := helpers.GetTraceeSliceStringArgumentByName(eventObj, "env")
		if err != nil {
			return nil
		}

		apiIPAddress := getApiAddressFromEnvs(envVars)
		if apiIPAddress != "" {
			sig.apiAddressContainerId[containerID] = apiIPAddress
		}
	case "security_socket_connect":
		apiAddress, exists := sig.apiAddressContainerId[containerID]
		if !exists {
			return nil
		}

		remoteAddr, err := helpers.GetRawAddrArgumentByName(eventObj, "remote_addr")
		if err != nil {
			return err
		}

		supportedFamily, err := helpers.IsInternetFamily(remoteAddr)
		if err != nil {
			return err
		}
		if !supportedFamily {
			return nil
		}

		ip, err := helpers.GetIPFromRawAddr(remoteAddr)
		if err != nil {
			return err
		}

		if ip == apiAddress {
			m, _ := sig.GetMetadata()
			sig.cb(&detect.Finding{
				SigMetadata: m,
				Event:       event,
				Data: map[string]interface{}{
					"ip": apiAddress,
				},
			})
		}
	}

	return nil
}

func (sig *K8sApiConnection) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *K8sApiConnection) Close() {}

func getApiAddressFromEnvs(envs []string) string {
	for _, env := range envs {
		if strings.Contains(env, "KUBERNETES_SERVICE_HOST=") {
			i := strings.Index(env, "=")
			return strings.TrimSpace(env[i+1:])
		}
	}
	return ""
}

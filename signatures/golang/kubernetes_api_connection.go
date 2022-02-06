package main

import (
	"fmt"
	"github.com/aquasecurity/tracee/types/trace"
	"strings"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
)

type K8sApiConnection struct {
	cb                    detect.SignatureHandler
	apiAddressContainerId map[string]string
}

func (sig *K8sApiConnection) Init(cb detect.SignatureHandler) error {
	sig.cb = cb
	sig.apiAddressContainerId = make(map[string]string)

	return nil
}

func (sig *K8sApiConnection) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "TRC-13",
		Version:     "0.1.0",
		Name:        "Kubernetes API server connection detected",
		Description: "A connection to the kubernetes API server was detected. The K8S API server is the brain of your K8S cluster, adversaries may try and communicate with the K8S API server to gather information/credentials, or even run more containers and laterally expand their grip on your systems.",
		Tags:        []string{"container"},
		Properties: map[string]interface{}{
			"Severity":     1,
			"MITRE ATT&CK": "Discovery: Cloud Service Discovery",
		},
	}, nil
}

func (sig *K8sApiConnection) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "execve", Origin: "container"},
		{Source: "tracee", Name: "security_socket_connect", Origin: "container"},
	}, nil
}

func (sig *K8sApiConnection) OnEvent(e detect.Event) error {
	eventObj, ok := e.(trace.TraceeEvent)
	if !ok {
		return fmt.Errorf("invalid event")
	}

	containerID := eventObj.ContainerID
	if containerID == "" {
		return nil
	}

	switch eventObj.EventName {

	case "execve":
		// the usage of 'envp' argument of the execve event is vulnerable to TOCTOU attack.
		// in the future we plan to add 'envp' argument to sched_process_exec, and when it'll happen, we should start
		// using sched_process_exec instead of execve in this signature.
		envpArg, err := helpers.GetTraceeArgumentByName(eventObj, "envp")
		if err != nil {
			return nil
		}
		envs := envpArg.Value.([]string)

		apiIPAddress := getApiAddressFromEnvs(envs)
		if apiIPAddress != "" {
			sig.apiAddressContainerId[containerID] = apiIPAddress
		}

	case "security_socket_connect":

		apiAddress, exists := sig.apiAddressContainerId[containerID]
		if !exists {
			return nil
		}

		remoteAddrArg, err := helpers.GetTraceeArgumentByName(eventObj, "remote_addr")
		if err != nil {
			return err
		}
		ip, err := getIPFromAddr(remoteAddrArg)
		if err != nil || ip == "" {
			return err
		}

		if ip == apiAddress {
			m, _ := sig.GetMetadata()
			sig.cb(detect.Finding{
				SigMetadata: m,
				Context:     eventObj,
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

func getIPFromAddr(addrArg trace.Argument) (string, error) {

	addr, isOk := addrArg.Value.(map[string]string)
	if !isOk {
		return "", fmt.Errorf("couldn't convert arg to addr")
	}

	if addr["sa_family"] == "AF_INET" {
		return addr["sin_addr"], nil
	} else if addr["sa_family"] == "AF_INET6" {
		return addr["sin6_addr"], nil
	}

	return "", nil
}

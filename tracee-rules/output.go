package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	tracee "github.com/aquasecurity/tracee/tracee-ebpf/tracee/external"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

const DetectionOutput string = `
*** Detection ***
Time: %d
Signature: %s
ProcessName: %s
ProcessID: %d
ParentProcessID: %d
Hostname: %s
EventName: %s
`

func setupOutput(resultWriter io.Writer, clock Clock, webhook string) (chan types.Finding, error) {
	out := make(chan types.Finding)
	go func() {
		for res := range out {
			sigMetadata, err := res.Signature.GetMetadata()
			if err != nil {
				log.Println("invalid signature metadata: ", err)
				continue
			}

			// TODO: Why is types.Finding.Context an interface?
			// Can it not be a concrete type like tracee.Event?
			processName := res.Context.(tracee.Event).ProcessName
			processID := res.Context.(tracee.Event).ProcessID
			parentProcessID := res.Context.(tracee.Event).ParentProcessID
			hostName := res.Context.(tracee.Event).HostName
			eventName := res.Context.(tracee.Event).EventName

			fmt.Fprintf(resultWriter, DetectionOutput, clock.Now().Unix(), sigMetadata.Name, processName, processID, parentProcessID, hostName, eventName)
			if webhook != "" {
				payload, err := prepareJSONPayload(res)
				if err != nil {
					log.Printf("error preparing json payload for %v: %v", res, err)
					continue
				}
				resp, err := http.Post(webhook, "application/json", strings.NewReader(payload))
				if err != nil {
					log.Printf("error calling webhook for %v: %v", res, err)
					continue
				}
				resp.Body.Close()
			}
		}
	}()
	return out, nil
}

func prepareJSONPayload(res types.Finding) (string, error) {
	// compatible with Falco webhook format, for easy integration with "falcosecurity/falcosidekick"
	// https://github.com/falcosecurity/falcosidekick/blob/e6b893f612e92352ba700bed9a19f1ec2cd18260/types/types.go#L12
	type Payload struct {
		Output       string                 `json:"output"`
		Priority     string                 `json:"priority,omitempty"`
		Rule         string                 `json:"rule"`
		Time         time.Time              `json:"time"`
		OutputFields map[string]interface{} `json:"output_fields"`
	}
	sigmeta, err := res.Signature.GetMetadata()
	if err != nil {
		return "", err
	}
	fields := make(map[string]interface{})
	if te, ok := res.Context.(tracee.Event); ok {
		fields["value"] = te.ReturnValue
	}
	payload := Payload{
		Output:       fmt.Sprintf("Rule \"%s\" detection:\n %v", sigmeta.Name, res.Data),
		Rule:         sigmeta.Name,
		Time:         time.Now(),
		OutputFields: fields,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return string(payloadJSON), nil
}

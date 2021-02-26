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
Time: %s
Signature ID: %s
Signature: %s
Data: %s
Command: %s
Hostname: %s
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

			switch res.Context.(type) {
			case tracee.Event:
				command := res.Context.(tracee.Event).ProcessName
				hostName := res.Context.(tracee.Event).HostName
				fmt.Fprintf(resultWriter, DetectionOutput, clock.Now().UTC().Format(time.RFC3339), sigMetadata.ID, sigMetadata.Name, res.Data, command, hostName)
			default:
				log.Printf("unsupported event detected: %T\n", res.Context)
				continue
			}

			if webhook != "" {
				if err := sendToWebhook(res, webhook, realClock{}); err != nil {
					log.Println(err)
				}
			}
		}
	}()
	return out, nil
}

func sendToWebhook(res types.Finding, webhook string, clock Clock) error {
	payload, err := prepareJSONPayload(res, clock)
	if err != nil {
		return fmt.Errorf("error preparing json payload for %v: %v", res, err)
	}
	resp, err := http.Post(webhook, "application/json", strings.NewReader(payload))
	if err != nil {
		return fmt.Errorf("error calling webhook for %v: %v", res, err)
	}
	resp.Body.Close()
	return nil
}

func prepareJSONPayload(res types.Finding, clock Clock) (string, error) {
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
		Time:         clock.Now(),
		OutputFields: fields,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return string(payloadJSON), nil
}

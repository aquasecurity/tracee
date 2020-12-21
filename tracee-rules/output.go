package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/aquasecurity/tracee/tracee-rules/types"
)

func setupOuput(webhook string) (chan types.Finding, error) {
	out := make(chan types.Finding)
	go func() {
		for res := range out {
			fmt.Printf("%+v\n", res)
			if webhook != "" {
				payload, err := prepareJSONPayload(res)
				if err != nil {
					log.Printf("error preparing json payload for %v: %v", res, err)
					continue
				}
				resp, err := http.Post(webhook, "application/json", strings.NewReader(payload))
				if err != nil {
					log.Printf("error calling webhook for %v: %v", res, err)
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
	sigmeta := res.Signature.GetMetadata()
	fields := make(map[string]interface{})
	if te, ok := res.Context.(types.TraceeEvent); ok {
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

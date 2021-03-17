package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"text/template"
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

func setupOutput(w io.Writer, clock Clock, webhook string, webhookTemplate string, contentType string, outputTemplate string) (chan types.Finding, error) {
	out := make(chan types.Finding)

	tWebhook, err := setupTemplate(webhookTemplate, clock)
	if err != nil && webhookTemplate != "" {
		return nil, fmt.Errorf("error preparing webhook template: %v", err)
	}

	tOutput, err := template.New(filepath.Base(outputTemplate)).
		Funcs(map[string]interface{}{
			"timeNow": func(unixTs float64) string {
				return clock.Now().UTC().Format("2006-01-02T15:04:05Z")
			},
		}).ParseFiles(outputTemplate)
	if err != nil && outputTemplate != "" {
		return nil, fmt.Errorf("error preparing output template: %v", err)
	}

	go func(w io.Writer, tWebhook, tOutput *template.Template) {
		for res := range out {
			sigMetadata, err := res.Signature.GetMetadata()
			if err != nil {
				log.Println("invalid signature metadata: ", err)
				continue
			}

			switch res.Context.(type) {
			case tracee.Event:
				if tOutput != nil {
					if err := tOutput.Execute(w, res); err != nil {
						log.Println("error writing to output: ", err)
					}
				} else {
					command := res.Context.(tracee.Event).ProcessName
					hostName := res.Context.(tracee.Event).HostName
					fmt.Fprintf(w, DetectionOutput, clock.Now().UTC().Format(time.RFC3339), sigMetadata.ID, sigMetadata.Name, res.Data, command, hostName)
				}
			default:
				log.Printf("unsupported event detected: %T\n", res.Context)
				continue
			}

			if webhook != "" {
				if err := sendToWebhook(tWebhook, res, webhook, webhookTemplate, contentType, realClock{}); err != nil {
					log.Println(err)
				}
			}
		}
	}(w, tWebhook, tOutput)
	return out, nil
}

func setupTemplate(webhookTemplate string, clock Clock) (*template.Template, error) {
	return template.New(filepath.Base(webhookTemplate)).
		Funcs(map[string]interface{}{
			"timeNow": func(unixTs float64) string {
				return clock.Now().UTC().Format("2006-01-02T15:04:05Z")
			},
		}).ParseFiles(webhookTemplate)
}

func sendToWebhook(t *template.Template, res types.Finding, webhook string, webhookTemplate string, contentType string, clock Clock) error {
	var payload string

	switch {
	case webhookTemplate != "":
		if t == nil {
			return fmt.Errorf("error writing to template: template not initialized")
		}
		if contentType == "" {
			log.Println("content-type was not set for the custom template: ", webhookTemplate)
		}
		buf := bytes.Buffer{}
		if err := t.Execute(&buf, res); err != nil {
			return fmt.Errorf("error writing to the template: %v", err)
		}
		payload = buf.String()

	default: // if no input template is specified, we send JSON by default
		contentType = "application/json"
		var err error
		payload, err = prepareJSONPayload(res, clock)
		if err != nil {
			return fmt.Errorf("error preparing json payload: %v", err)
		}
	}

	resp, err := http.Post(webhook, contentType, strings.NewReader(payload))
	if err != nil {
		return fmt.Errorf("error calling webhook %v", err)
	}
	_ = resp.Body.Close()
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
		Time:         clock.Now().UTC(),
		OutputFields: fields,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return string(payloadJSON), nil
}

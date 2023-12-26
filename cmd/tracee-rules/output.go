package main

import (
	"bytes"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/Masterminds/sprig/v3"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
)

const DefaultDetectionOutputTemplate string = `
*** Detection ***
Time: {{ dateInZone "2006-01-02T15:04:05Z" (now) "UTC" }}
Signature ID: {{ .SigMetadata.ID }}
Signature: {{ .SigMetadata.Name }}
Data: {{ .Data }}
Command: {{ .Event.Payload.ProcessName }}
Hostname: {{ .Event.Payload.HostName }}
`

func setupTemplate(inputTemplateFile string) (*template.Template, error) {
	switch {
	case inputTemplateFile != "":
		return template.New(filepath.Base(inputTemplateFile)).
			Funcs(sprig.TxtFuncMap()).
			ParseFiles(inputTemplateFile)
	default:
		return template.New("default").
			Funcs(sprig.TxtFuncMap()).
			Parse(DefaultDetectionOutputTemplate)
	}
}

func setupOutput(w io.Writer, webhook string, webhookTemplate string, contentType string, outputTemplate string) (chan *detect.Finding, error) {
	out := make(chan *detect.Finding)
	var err error

	var tWebhook *template.Template
	tWebhook, err = setupTemplate(webhookTemplate)
	if err != nil && webhookTemplate != "" {
		return nil, errfmt.Errorf("error preparing webhook template: %v", err)
	}

	var tOutput *template.Template
	tOutput, err = setupTemplate(outputTemplate)
	if err != nil && outputTemplate != "" {
		return nil, errfmt.Errorf("error preparing output template: %v", err)
	}

	go func(w io.Writer, tWebhook, tOutput *template.Template) {
		for res := range out {
			switch res.Event.Payload.(type) {
			case trace.Event:
				if err := tOutput.Execute(w, res); err != nil {
					logger.Errorw("Writing to output: " + err.Error())
				}
			default:
				logger.Warnw("Unsupported event detected: " + res.Event.Payload.(string))
				continue
			}

			if webhook != "" {
				if err := sendToWebhook(tWebhook, res, webhook, webhookTemplate, contentType); err != nil {
					logger.Errorw("Sending to webhook: " + err.Error())
				}
			}
		}
	}(w, tWebhook, tOutput)
	return out, nil
}

func sendToWebhook(t *template.Template, res *detect.Finding, webhook string, webhookTemplate string, contentType string) error {
	var payload string

	switch {
	case webhookTemplate != "":
		if t == nil {
			return errfmt.Errorf("error writing to template: template not initialized")
		}
		if contentType == "" {
			logger.Warnw("Content-type was not set for the custom template: " + webhookTemplate)
		}
		buf := bytes.Buffer{}
		if err := t.Execute(&buf, res); err != nil {
			return errfmt.Errorf("error writing to the template: %v", err)
		}
		payload = buf.String()
	default:
		return errfmt.Errorf("error sending to webhook: --webhook-template flag is required when using --webhook flag")
	}

	resp, err := http.Post(webhook, contentType, strings.NewReader(payload))
	if err != nil {
		return errfmt.Errorf("error calling webhook %v", err)
	}
	_ = resp.Body.Close()
	return nil
}

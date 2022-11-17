package flags

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/aquasecurity/tracee/pkg/webhook"
)

func webhookHelp() string {
	return `Send events to an webhook endpoint.
possible options:
url                             webhook endpoint url.
timeout=1s                      request timeout, values too large might slow down the pipeline.
format=json                     format payload as json.

Examples:
  --webhook url=http://test --webhook format=json                    | send webhook to http://test as json
  --webhook url=http://test --webhook timeout=2s                     | send webhook to http://test with a timeout of 2s

Use this flag multiple times to choose multiple output options
`
}

func PrepareWebhook(webhookSlice []string) (webhook.Webhook, error) {
	w := webhook.Webhook{
		// defaults
		Format:  "json",
		Timeout: time.Second * 1,
	}

	for _, s := range webhookSlice {
		optValue := strings.Split(s, "=")
		switch optValue[0] {
		case "url":
			_, err := url.ParseRequestURI(optValue[1])
			if err != nil {
				return webhook.Webhook{}, fmt.Errorf("invalid webhook url %v", err.Error())
			}

			w.URL = optValue[1]
		case "timeout":
			timeout, err := time.ParseDuration(optValue[1])
			if err != nil {
				return webhook.Webhook{}, fmt.Errorf("invalid webhook timeout %v", err.Error())
			}

			w.Timeout = timeout
		case "format":
			if optValue[1] != "json" {
				return webhook.Webhook{}, fmt.Errorf("invalid webhook format %q", optValue[1])
			}

			w.Format = optValue[1]
		default:
			return webhook.Webhook{}, errors.New("invalid webhook option specified, use '--webhook help' for more info")
		}
	}

	return w, nil
}

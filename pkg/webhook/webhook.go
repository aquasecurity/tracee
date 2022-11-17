package webhook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/trace"
)

type Webhook struct {
	URL     string
	Format  string
	Timeout time.Duration
}

func (w Webhook) Send(event trace.Event) error {
	// ignore if empty
	if w.URL == "" {
		return nil
	}

	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}

	client := http.Client{Timeout: w.Timeout}

	req, err := http.NewRequest(http.MethodPost, w.URL, bytes.NewReader(payload))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", w.getContentType())

	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		logger.Error(fmt.Sprintf("error sending webhook, http status: %d", resp.StatusCode))
	}

	_ = resp.Body.Close()

	return nil
}

func (w Webhook) getContentType() string {
	return "application/json"
}

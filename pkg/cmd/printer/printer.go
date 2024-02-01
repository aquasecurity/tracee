package printer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"

	forward "github.com/IBM/fluent-forward-go/fluent/client"
	"github.com/Masterminds/sprig/v3"

	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/metrics"
	"github.com/aquasecurity/tracee/types/trace"
)

type EventPrinter interface {
	// Init serves as the initializer method for every event Printer type
	Init() error
	// Preamble prints something before event printing begins (one time)
	Preamble()
	// Epilogue prints something after event printing ends (one time)
	Epilogue(stats metrics.Stats)
	// Print prints a single event
	Print(event trace.Event)
	// dispose of resources
	Close()
}

func New(cfg config.PrinterConfig) (EventPrinter, error) {
	var res EventPrinter
	kind := cfg.Kind

	if cfg.OutFile == nil {
		return res, errfmt.Errorf("out file is not set")
	}

	switch {
	case kind == "ignore":
		res = &ignoreEventPrinter{}
	case kind == "table":
		res = &tableEventPrinter{
			out:           cfg.OutFile,
			verbose:       false,
			containerMode: cfg.ContainerMode,
			relativeTS:    cfg.RelativeTS,
		}
	case kind == "table-verbose":
		res = &tableEventPrinter{
			out:           cfg.OutFile,
			verbose:       true,
			containerMode: cfg.ContainerMode,
			relativeTS:    cfg.RelativeTS,
		}
	case kind == "json":
		res = &jsonEventPrinter{
			out: cfg.OutFile,
		}
	case kind == "forward":
		res = &forwardEventPrinter{
			outPath: cfg.OutPath,
		}
	case kind == "webhook":
		res = &webhookEventPrinter{
			outPath: cfg.OutPath,
		}
	case strings.HasPrefix(kind, "gotemplate="):
		res = &templateEventPrinter{
			out:          cfg.OutFile,
			templatePath: strings.Split(kind, "=")[1],
		}
	}
	err := res.Init()
	if err != nil {
		return nil, err
	}
	return res, nil
}

type tableEventPrinter struct {
	out           io.WriteCloser
	verbose       bool
	containerMode config.ContainerMode
	relativeTS    bool
}

func (p tableEventPrinter) Init() error { return nil }

func (p tableEventPrinter) Preamble() {
	if p.verbose {
		switch p.containerMode {
		case config.ContainerModeDisabled:
			fmt.Fprintf(p.out,
				"%-16s %-17s %-13s %-12s %-12s %-6s %-16s %-7s %-7s %-7s %-16s %-25s %s",
				"TIME",
				"UTS_NAME",
				"CONTAINER_ID",
				"MNT_NS",
				"PID_NS",
				"UID",
				"COMM",
				"PID",
				"TID",
				"PPID",
				"RET",
				"EVENT",
				"ARGS",
			)
		case config.ContainerModeEnabled:
			fmt.Fprintf(p.out,
				"%-16s %-17s %-13s %-12s %-12s %-6s %-16s %-15s %-15s %-15s %-16s %-25s %s",
				"TIME",
				"UTS_NAME",
				"CONTAINER_ID",
				"MNT_NS",
				"PID_NS",
				"UID",
				"COMM",
				"PID/host",
				"TID/host",
				"PPID/host",
				"RET",
				"EVENT",
				"ARGS",
			)
		case config.ContainerModeEnriched:
			fmt.Fprintf(p.out,
				"%-16s %-17s %-13s %-16s %-12s %-12s %-6s %-16s %-15s %-15s %-15s %-16s %-25s %s",
				"TIME",
				"UTS_NAME",
				"CONTAINER_ID",
				"IMAGE",
				"MNT_NS",
				"PID_NS",
				"UID",
				"COMM",
				"PID/host",
				"TID/host",
				"PPID/host",
				"RET",
				"EVENT",
				"ARGS",
			)
		}
	} else {
		switch p.containerMode {
		case config.ContainerModeDisabled:
			fmt.Fprintf(p.out,
				"%-16s %-6s %-16s %-7s %-7s %-16s %-25s %s",
				"TIME",
				"UID",
				"COMM",
				"PID",
				"TID",
				"RET",
				"EVENT",
				"ARGS",
			)
		case config.ContainerModeEnabled:
			fmt.Fprintf(p.out,
				"%-16s %-13s %-6s %-16s %-15s %-15s %-16s %-25s %s",
				"TIME",
				"CONTAINER_ID",
				"UID",
				"COMM",
				"PID/host",
				"TID/host",
				"RET",
				"EVENT",
				"ARGS",
			)
		case config.ContainerModeEnriched:
			fmt.Fprintf(p.out,
				"%-16s %-13s %-16s %-6s %-16s %-15s %-15s %-16s %-25s %s",
				"TIME",
				"CONTAINER_ID",
				"IMAGE",
				"UID",
				"COMM",
				"PID/host",
				"TID/host",
				"RET",
				"EVENT",
				"ARGS",
			)
		}
	}
	fmt.Fprintln(p.out)
}

func (p tableEventPrinter) Print(event trace.Event) {
	ut := time.Unix(0, int64(event.Timestamp))
	if p.relativeTS {
		ut = ut.UTC()
	}
	timestamp := fmt.Sprintf("%02d:%02d:%02d:%06d", ut.Hour(), ut.Minute(), ut.Second(), ut.Nanosecond()/1000)

	containerId := event.Container.ID
	if len(containerId) > 12 {
		containerId = containerId[:12]
	}
	containerImage := event.Container.ImageName
	if len(containerImage) > 16 {
		containerImage = containerImage[:16]
	}

	eventName := event.EventName
	if len(eventName) > 25 {
		eventName = eventName[:22] + "..."
	}

	if p.verbose {
		switch p.containerMode {
		case config.ContainerModeDisabled:
			fmt.Fprintf(p.out,
				"%-16s %-17s %-13s %-12d %-12d %-6d %-16s %-7d %-7d %-7d %-16d %-25s ",
				timestamp,
				event.HostName,
				containerId,
				event.MountNS,
				event.PIDNS,
				event.UserID,
				event.ProcessName,
				event.ProcessID,
				event.ThreadID,
				event.ParentProcessID,
				event.ReturnValue,
				event.EventName,
			)
		case config.ContainerModeEnabled:
			fmt.Fprintf(p.out,
				"%-16s %-17s %-13s %-12d %-12d %-6d %-16s %-7d/%-7d %-7d/%-7d %-7d/%-7d %-16d %-25s ",
				timestamp,
				event.HostName,
				containerId,
				event.MountNS,
				event.PIDNS,
				event.UserID,
				event.ProcessName,
				event.ProcessID,
				event.HostProcessID,
				event.ThreadID,
				event.HostThreadID,
				event.ParentProcessID,
				event.HostParentProcessID,
				event.ReturnValue,
				event.EventName,
			)
		case config.ContainerModeEnriched:
			fmt.Fprintf(p.out,
				"%-16s %-17s %-13s %-16s %-12d %-12d %-6d %-16s %-7d/%-7d %-7d/%-7d %-7d/%-7d %-16d %-25s ",
				timestamp,
				event.HostName,
				containerId,
				event.Container.ImageName,
				event.MountNS,
				event.PIDNS,
				event.UserID,
				event.ProcessName,
				event.ProcessID,
				event.HostProcessID,
				event.ThreadID,
				event.HostThreadID,
				event.ParentProcessID,
				event.HostParentProcessID,
				event.ReturnValue,
				event.EventName,
			)
		}
	} else {
		switch p.containerMode {
		case config.ContainerModeDisabled:
			fmt.Fprintf(p.out,
				"%-16s %-6d %-16s %-7d %-7d %-16d %-25s ",
				timestamp,
				event.UserID,
				event.ProcessName,
				event.ProcessID,
				event.ThreadID,
				event.ReturnValue,
				eventName,
			)
		case config.ContainerModeEnabled:
			fmt.Fprintf(p.out,
				"%-16s %-13s %-6d %-16s %-7d/%-7d %-7d/%-7d %-16d %-25s ",
				timestamp,
				containerId,
				event.UserID,
				event.ProcessName,
				event.ProcessID,
				event.HostProcessID,
				event.ThreadID,
				event.HostThreadID,
				event.ReturnValue,
				eventName,
			)
		case config.ContainerModeEnriched:
			fmt.Fprintf(p.out,
				"%-16s %-13s %-16s %-6d %-16s %-7d/%-7d %-7d/%-7d %-16d %-25s ",
				timestamp,
				containerId,
				containerImage,
				event.UserID,
				event.ProcessName,
				event.ProcessID,
				event.HostProcessID,
				event.ThreadID,
				event.HostThreadID,
				event.ReturnValue,
				eventName,
			)
		}
	}
	for i, arg := range event.Args {
		name := arg.Name
		value := arg.Value

		// triggeredBy from pkg/ebpf/finding.go breaks the table output,
		// so we simplify it
		if name == "triggeredBy" {
			value = fmt.Sprintf("%s", value.(map[string]interface{})["name"])
		}

		if i == 0 {
			fmt.Fprintf(p.out, "%s: %v", name, value)
		} else {
			fmt.Fprintf(p.out, ", %s: %v", name, value)
		}
	}
	fmt.Fprintln(p.out)
}

func (p tableEventPrinter) Epilogue(stats metrics.Stats) {
	fmt.Println()
	fmt.Fprintf(p.out, "End of events stream\n")
	fmt.Fprintf(p.out, "Stats: %+v\n", stats)
}

func (p tableEventPrinter) Close() {
}

type templateEventPrinter struct {
	out          io.WriteCloser
	templatePath string
	templateObj  **template.Template
}

func (p *templateEventPrinter) Init() error {
	tmplPath := p.templatePath
	if tmplPath == "" {
		return errfmt.Errorf("please specify a gotemplate for event-based output")
	}
	tmpl, err := template.ParseFiles(tmplPath)
	if err != nil {
		return errfmt.WrapError(err)
	}
	p.templateObj = &tmpl

	return nil
}

func (p templateEventPrinter) Preamble() {}

func (p templateEventPrinter) Print(event trace.Event) {
	if p.templateObj != nil {
		err := (*p.templateObj).Execute(p.out, event)
		if err != nil {
			logger.Errorw("Error executing template", "error", err)
		}
	} else {
		fmt.Fprintf(p.out, "Template Obj is nil")
	}
}

func (p templateEventPrinter) Epilogue(stats metrics.Stats) {}

func (p templateEventPrinter) Close() {
}

type jsonEventPrinter struct {
	out io.WriteCloser
}

func (p jsonEventPrinter) Init() error { return nil }

func (p jsonEventPrinter) Preamble() {}

func (p jsonEventPrinter) Print(event trace.Event) {
	eBytes, err := json.Marshal(event)
	if err != nil {
		logger.Errorw("Error marshaling event to json", "error", err)
	}
	fmt.Fprintln(p.out, string(eBytes))
}

func (p jsonEventPrinter) Epilogue(stats metrics.Stats) {}

func (p jsonEventPrinter) Close() {
}

// ignoreEventPrinter ignores events
type ignoreEventPrinter struct{}

func (p *ignoreEventPrinter) Init() error {
	return nil
}

func (p *ignoreEventPrinter) Preamble() {}

func (p *ignoreEventPrinter) Print(event trace.Event) {}

func (p *ignoreEventPrinter) Epilogue(stats metrics.Stats) {}

func (p ignoreEventPrinter) Close() {}

// forwardEventPrinter sends events over the Fluent Forward protocol to a receiver
type forwardEventPrinter struct {
	outPath string
	url     *url.URL
	client  *forward.Client
	// These parameters can be set up from the URL
	tag string `default:"tracee"`
}

func getParameterValue(parameters url.Values, key string, defaultValue string) string {
	param, found := parameters[key]
	// Ensure we have a non-empty parameter set for this key
	if found && param[0] != "" {
		return param[0]
	}
	// Otherwise use the default value
	return defaultValue
}

func (p *forwardEventPrinter) Init() error {
	// Now parse the optional parameters with defaults and some basic verification
	u, err := url.Parse(p.outPath)
	if err != nil {
		return fmt.Errorf("unable to parse URL %q: %w", p.url, err)
	}
	p.url = u

	parameters, _ := url.ParseQuery(p.url.RawQuery)

	// Check if we have a tag set or default it
	p.tag = getParameterValue(parameters, "tag", "tracee")

	// Do we want to enable requireAck?
	requireAckString := getParameterValue(parameters, "requireAck", "false")
	requireAck, err := strconv.ParseBool(requireAckString)
	if err != nil {
		return errfmt.Errorf("unable to convert requireAck value %q: %v", requireAckString, err)
	}

	// Timeout conversion from string
	timeoutValueString := getParameterValue(parameters, "connectionTimeout", "10s")
	connectionTimeout, err := time.ParseDuration(timeoutValueString)
	if err != nil {
		return errfmt.Errorf("unable to convert connectionTimeout value %q: %v", timeoutValueString, err)
	}

	// We should have both username and password or neither for basic auth
	username := p.url.User.Username()
	password, isPasswordSet := p.url.User.Password()
	if username != "" && !isPasswordSet {
		return errfmt.Errorf("missing basic auth configuration for Forward destination")
	}

	// Ensure we support tcp or udp protocols
	protocol := "tcp"
	if p.url.Scheme != "" {
		protocol = p.url.Scheme
	}
	if protocol != "tcp" && protocol != "udp" {
		return errfmt.Errorf("unsupported protocol for Forward destination: %s", protocol)
	}

	// Extract the host (and port)
	address := p.url.Host
	logger.Infow("Attempting to connect to Forward destination", "url", address, "tag", p.tag)

	// Create a TCP connection to the forward receiver
	p.client = forward.New(forward.ConnectionOptions{
		Factory: &forward.ConnFactory{
			Network: protocol,
			Address: address,
		},
		RequireAck:        requireAck,
		ConnectionTimeout: connectionTimeout,
		AuthInfo: forward.AuthInfo{
			Username: username,
			Password: password,
		},
	})

	err = p.client.Connect()
	if err != nil {
		// The destination may not be available but may appear later so do not return an error here and just connect later.
		logger.Errorw("Error connecting to Forward destination", "url", p.url.String(), "error", err)
	}
	return nil
}

func (p *forwardEventPrinter) Preamble() {}

func (p *forwardEventPrinter) Print(event trace.Event) {
	if p.client == nil {
		logger.Errorw("Invalid Forward client")
		return
	}

	// The actual event is marshalled as JSON then sent with the other information (tag, etc.)
	eBytes, err := json.Marshal(event)
	if err != nil {
		logger.Errorw("Error marshaling event to json", "error", err)
	}

	record := map[string]interface{}{
		"event": string(eBytes),
	}

	err = p.client.SendMessage(p.tag, record)
	// Assuming all is well we continue but if the connection is dropped or some other error we retry
	if err != nil {
		logger.Errorw("Error writing to Forward destination", "destination", p.url.Host, "tag", p.tag, "error", err)
		// Try five times to reconnect and send before giving up
		// TODO: consider using go-kit for circuit break, retry, etc
		for attempts := 0; attempts < 5; attempts++ {
			// Attempt to reconnect (remote end may have dropped/restarted)
			err = p.client.Reconnect()
			if err == nil {
				// Re-attempt to send
				err = p.client.SendMessage(p.tag, record)
				if err == nil {
					break
				}
			}
		}
	}
}

func (p *forwardEventPrinter) Epilogue(stats metrics.Stats) {}

func (p forwardEventPrinter) Close() {
	if p.client != nil {
		logger.Infow("Disconnecting from Forward destination", "url", p.url.Host, "tag", p.tag)
		if err := p.client.Disconnect(); err != nil {
			logger.Errorw("Disconnecting from Forward destination", "error", err)
		}
	}
}

type webhookEventPrinter struct {
	outPath     string
	url         *url.URL
	timeout     time.Duration
	templateObj *template.Template
	contentType string
}

func (ws *webhookEventPrinter) Init() error {
	u, err := url.Parse(ws.outPath)
	if err != nil {
		return errfmt.Errorf("unable to parse URL %q: %v", ws.outPath, err)
	}
	ws.url = u

	parameters, _ := url.ParseQuery(ws.url.RawQuery)

	timeout := getParameterValue(parameters, "timeout", "10s")
	t, err := time.ParseDuration(timeout)
	if err != nil {
		return errfmt.Errorf("unable to convert timeout value %q: %v", timeout, err)
	}
	ws.timeout = t

	gotemplate := getParameterValue(parameters, "gotemplate", "")
	if gotemplate != "" {
		tmpl, err := template.New(filepath.Base(gotemplate)).
			Funcs(sprig.TxtFuncMap()).
			ParseFiles(gotemplate)

		if err != nil {
			return errfmt.WrapError(err)
		}
		ws.templateObj = tmpl
	}

	contentType := getParameterValue(parameters, "contentType", "application/json")
	ws.contentType = contentType

	return nil
}

func (ws *webhookEventPrinter) Preamble() {}

func (ws *webhookEventPrinter) Print(event trace.Event) {
	var (
		payload []byte
		err     error
	)

	if ws.templateObj != nil {
		buf := bytes.Buffer{}
		if err := ws.templateObj.Execute(&buf, event); err != nil {
			logger.Errorw("error writing to the template", "error", err)
			return
		}
		payload = buf.Bytes()
	} else {
		payload, err = json.Marshal(event)
		if err != nil {
			logger.Errorw("Error marshalling event", "error", err)
			return
		}
	}

	client := http.Client{Timeout: ws.timeout}

	req, err := http.NewRequest(http.MethodPost, ws.url.String(), bytes.NewReader(payload))
	if err != nil {
		logger.Errorw("Error creating request", "error", err)
		return
	}

	req.Header.Set("Content-Type", ws.contentType)

	resp, err := client.Do(req)
	if err != nil {
		logger.Errorw("Error sending webhook", "error", err)
		return
	}

	if resp.StatusCode != http.StatusOK {
		logger.Errorw(fmt.Sprintf("Error sending webhook, http status: %d", resp.StatusCode))
	}

	_ = resp.Body.Close()
}

func (ws *webhookEventPrinter) Epilogue(stats metrics.Stats) {}

func (ws *webhookEventPrinter) Close() {
}

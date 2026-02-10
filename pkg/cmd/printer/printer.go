package printer

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"

	forward "github.com/IBM/fluent-forward-go/fluent/client"
	"github.com/Masterminds/sprig/v3"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/metrics"
	"github.com/aquasecurity/tracee/pkg/streams"
)

// EventPrinter is the interface for all event printers.
type EventPrinter interface {
	// Init serves as the initializer method for every event Printer type
	Init() error
	// Preamble prints something before event printing begins (one time)
	Preamble()
	// Epilogue prints something after event printing ends (one time)
	Epilogue(stats metrics.Stats)
	// Print prints a single event
	Print(event *pb.Event)
	// Receive events from stream
	FromStream(stream *streams.Stream)
	// Mainly created for testing purposes. Might be useful also in other context
	Kind() string
	// dispose of resources
	Close()
}

// New creates a new EventPrinter based on the destinations.
func New(destinations []config.Destination) (EventPrinter, error) {
	if len(destinations) == 0 {
		return nil, errfmt.Errorf("destinations can't be empty")
	}

	if len(destinations) > 1 {
		return newBroadcast(destinations)
	}

	return newSinglePrinter(destinations[0])
}

// newSinglePrinter creates a new EventPrinter based on the destination.
func newSinglePrinter(dst config.Destination) (EventPrinter, error) {
	var res EventPrinter
	kind := dst.Type
	format := dst.Format

	if dst.Type == "file" && dst.File == nil {
		return res, errfmt.Errorf("out file is not set")
	}

	switch {
	case kind == "ignore":
		res = &ignoreEventPrinter{}
	case kind == "file":
		switch {
		case format == "table":
			res = &tableEventPrinter{
				out:           dst.File,
				containerMode: dst.ContainerMode,
			}
		case format == "json":
			res = &jsonEventPrinter{
				out: dst.File,
			}
		case strings.HasPrefix(format, "gotemplate="):
			res = &templateEventPrinter{
				out:          dst.File,
				templatePath: strings.Split(format, "=")[1],
			}
		}
	case kind == "forward":
		res = &forwardEventPrinter{
			outPath: dst.Url,
		}
	case kind == "webhook":
		res = &webhookEventPrinter{
			outPath: dst.Url,
			format:  dst.Format,
		}
	}

	err := res.Init()
	if err != nil {
		return nil, err
	}

	return res, nil
}

// tableEventPrinter is the printer for the table format.
type tableEventPrinter struct {
	out           io.WriteCloser
	containerMode config.ContainerMode
	relativeTS    bool
}

// Init initializes the tableEventPrinter.
func (p tableEventPrinter) Init() error {
	return nil
}

// Preamble prints the preamble for the table format.
func (p tableEventPrinter) Preamble() {
	switch p.containerMode {
	case config.ContainerModeDisabled:
		fmt.Fprintf(p.out,
			"%-16s %-6s %-16s %-7s %-7s %-25s %s",
			"TIME",
			"UID",
			"COMM",
			"PID",
			"TID",
			"EVENT",
			"ARGS",
		)
	case config.ContainerModeEnabled:
		fmt.Fprintf(p.out,
			"%-16s %-13s %-6s %-16s %-15s %-15s %-25s %s",
			"TIME",
			"CONTAINER_ID",
			"UID",
			"COMM",
			"PID/host",
			"TID/host",
			"EVENT",
			"ARGS",
		)
	case config.ContainerModeEnriched:
		fmt.Fprintf(p.out,
			"%-16s %-13s %-16s %-6s %-16s %-15s %-15s %-25s %s",
			"TIME",
			"CONTAINER_ID",
			"IMAGE",
			"UID",
			"COMM",
			"PID/host",
			"TID/host",
			"EVENT",
			"ARGS",
		)
	}
	fmt.Fprintln(p.out)
}

// Print prints a single event in the table format.
func (p tableEventPrinter) Print(event *pb.Event) {
	if event == nil {
		return
	}

	// Extract timestamp
	timestamp := "N/A"
	if event.Timestamp != nil {
		ut := event.Timestamp.AsTime()
		if p.relativeTS {
			ut = ut.UTC()
		}
		timestamp = fmt.Sprintf("%02d:%02d:%02d:%06d", ut.Hour(), ut.Minute(), ut.Second(), ut.Nanosecond()/1000)
	}

	// Extract container ID
	containerId := ""
	if event.Workload != nil && event.Workload.Container != nil {
		containerId = event.Workload.Container.Id
		if len(containerId) > 12 {
			containerId = containerId[:12]
		}
	}

	// Extract container image
	containerImage := ""
	if event.Workload != nil && event.Workload.Container != nil && event.Workload.Container.Image != nil {
		containerImage = event.Workload.Container.Image.Name
		if len(containerImage) > 16 {
			containerImage = containerImage[:16]
		}
	}

	// Extract event name
	eventName := event.Name
	if len(eventName) > 25 {
		eventName = eventName[:22] + "..."
	}

	// Extract process fields
	var userId, processName string
	var processID, threadID, hostProcessID, hostThreadID int

	if event.Workload != nil && event.Workload.Process != nil {
		if event.Workload.Process.RealUser != nil && event.Workload.Process.RealUser.Id != nil {
			userId = fmt.Sprintf("%d", event.Workload.Process.RealUser.Id.Value)
		}
		if event.Workload.Process.Thread != nil {
			processName = event.Workload.Process.Thread.Name
			if event.Workload.Process.Thread.Tid != nil {
				threadID = int(event.Workload.Process.Thread.Tid.Value)
			}
			if event.Workload.Process.Thread.HostTid != nil {
				hostThreadID = int(event.Workload.Process.Thread.HostTid.Value)
			}
		}
		if event.Workload.Process.Pid != nil {
			processID = int(event.Workload.Process.Pid.Value)
		}
		if event.Workload.Process.HostPid != nil {
			hostProcessID = int(event.Workload.Process.HostPid.Value)
		}
	}

	switch p.containerMode {
	case config.ContainerModeDisabled:
		fmt.Fprintf(p.out,
			"%-16s %-6s %-16s %-7d %-7d %-25s ",
			timestamp,
			userId,
			processName,
			processID,
			threadID,
			eventName,
		)
	case config.ContainerModeEnabled:
		fmt.Fprintf(p.out,
			"%-16s %-13s %-6s %-16s %-7d/%-7d %-7d/%-7d %-25s ",
			timestamp,
			containerId,
			userId,
			processName,
			processID,
			hostProcessID,
			threadID,
			hostThreadID,
			eventName,
		)
	case config.ContainerModeEnriched:
		fmt.Fprintf(p.out,
			"%-16s %-13s %-16s %-6s %-16s %-7d/%-7d %-7d/%-7d %-25s ",
			timestamp,
			containerId,
			containerImage,
			userId,
			processName,
			processID,
			hostProcessID,
			threadID,
			hostThreadID,
			eventName,
		)
	}

	// Print event data (args)
	for i, data := range event.Data {
		name := data.Name
		var value interface{}

		// Get the actual value from the EventValue union
		switch v := data.Value.(type) {
		case *pb.EventValue_Int32:
			value = v.Int32
		case *pb.EventValue_Int64:
			value = v.Int64
		case *pb.EventValue_UInt32:
			value = v.UInt32
		case *pb.EventValue_UInt64:
			value = v.UInt64
		case *pb.EventValue_Str:
			value = v.Str
		case *pb.EventValue_Bytes:
			value = v.Bytes
		case *pb.EventValue_Bool:
			value = v.Bool
		case *pb.EventValue_StrArray:
			value = v.StrArray.Value
		case *pb.EventValue_Int32Array:
			value = v.Int32Array.Value
		case *pb.EventValue_UInt64Array:
			value = v.UInt64Array.Value
		case *pb.EventValue_Sockaddr:
			value = v.Sockaddr
		case *pb.EventValue_Credentials:
			value = v.Credentials
		case *pb.EventValue_Timespec:
			value = v.Timespec
		case *pb.EventValue_HookedSyscalls:
			value = v.HookedSyscalls
		case *pb.EventValue_HookedSeqOps:
			value = v.HookedSeqOps
		case *pb.EventValue_Ipv4:
			value = v.Ipv4
		case *pb.EventValue_Ipv6:
			value = v.Ipv6
		case *pb.EventValue_Tcp:
			value = v.Tcp
		case *pb.EventValue_Udp:
			value = v.Udp
		case *pb.EventValue_Icmp:
			value = v.Icmp
		case *pb.EventValue_Icmpv6:
			value = v.Icmpv6
		case *pb.EventValue_Dns:
			value = v.Dns
		case *pb.EventValue_DnsQuestions:
			value = v.DnsQuestions
		case *pb.EventValue_DnsResponses:
			value = v.DnsResponses
		case *pb.EventValue_PacketMetadata:
			value = v.PacketMetadata
		case *pb.EventValue_Http:
			value = v.Http
		case *pb.EventValue_HttpRequest:
			value = v.HttpRequest
		case *pb.EventValue_HttpResponse:
			value = v.HttpResponse
		case *pb.EventValue_Struct:
			value = v.Struct
		default:
			value = "<unknown>"
		}

		// detectedFrom argument breaks the table output, so we simplify it
		if name == "detectedFrom" && event.DetectedFrom != nil {
			value = event.DetectedFrom.Name
		}

		if i == 0 {
			fmt.Fprintf(p.out, "%s: %v", name, value)
		} else {
			fmt.Fprintf(p.out, ", %s: %v", name, value)
		}
	}
	fmt.Fprintln(p.out)
}

// Epilogue prints the epilogue for the table format.
func (p tableEventPrinter) Epilogue(stats metrics.Stats) {
	fmt.Println()
	fmt.Fprint(p.out, "End of events stream\n")

	jsonStats, err := stats.MarshalJSON()
	if err != nil {
		logger.Errorw("Error marshaling stats to json", "error", err)
	}
	fmt.Fprintf(p.out, "%s\n", string(jsonStats))
}

// FromStream receives events from the stream and prints them in the table format.
func (p *tableEventPrinter) FromStream(stream *streams.Stream) {
	consumeFromStream(stream, p)
}

// Kind returns the kind of the tableEventPrinter.
func (p *tableEventPrinter) Kind() string {
	return "table"
}

// Close closes the tableEventPrinter.
func (p tableEventPrinter) Close() {
	// Sync flushes buffered data, ensuring events aren't lost on process exit
	if f, ok := p.out.(*os.File); ok {
		_ = f.Sync()
	}
}

// templateEventPrinter is the printer for the template format.
type templateEventPrinter struct {
	out          io.WriteCloser
	templatePath string
	templateObj  **template.Template
}

// Init initializes the templateEventPrinter.
func (p *templateEventPrinter) Init() error {
	tmplPath := p.templatePath
	if tmplPath == "" {
		return errfmt.Errorf("please specify a gotemplate for event-based output")
	}
	tmpl, err := template.New(filepath.Base(tmplPath)).
		Funcs(sprig.TxtFuncMap()).
		ParseFiles(tmplPath)
	if err != nil {
		return errfmt.WrapError(err)
	}
	p.templateObj = &tmpl

	return nil
}

// Preamble prints the preamble for the template format.
func (p templateEventPrinter) Preamble() {}

// Print prints a single event in the template format.
func (p templateEventPrinter) Print(event *pb.Event) {
	if p.templateObj != nil {
		err := (*p.templateObj).Execute(p.out, event)
		if err != nil {
			logger.Errorw("Error executing template", "error", err)
		}
	} else {
		fmt.Fprint(p.out, "Template Obj is nil")
	}
}

// Epilogue prints the epilogue for the template format.
func (p templateEventPrinter) Epilogue(stats metrics.Stats) {}

// FromStream receives events from the stream and prints them using the template format.
func (p *templateEventPrinter) FromStream(stream *streams.Stream) {
	consumeFromStream(stream, p)
}

// Kind returns the kind of the templateEventPrinter.
func (p *templateEventPrinter) Kind() string {
	return "template"
}

// Close closes the templateEventPrinter and flushes buffered data.
func (p templateEventPrinter) Close() {
	// Sync flushes buffered data, ensuring events aren't lost on process exit
	if f, ok := p.out.(*os.File); ok {
		_ = f.Sync()
	}
}

// jsonEventPrinter is the printer for the JSON format.
type jsonEventPrinter struct {
	out              io.WriteCloser
	buffer           *bufio.Writer
	eventCount       int64
	lastFlush        time.Time
	isStdoutOrStderr bool // flush immediately for interactive output
}

// Init initializes the jsonEventPrinter with a buffered writer.
func (p *jsonEventPrinter) Init() error {
	// Detect if output is stdout/stderr for immediate flushing (interactive use)
	// vs file output where we want buffering for performance
	if f, ok := p.out.(*os.File); ok {
		p.isStdoutOrStderr = f == os.Stdout || f == os.Stderr
	}

	// Use 256KB buffer - good performance while allowing frequent flushes
	p.buffer = bufio.NewWriterSize(p.out, 256*1024)
	p.eventCount = 0
	p.lastFlush = time.Now()
	return nil
}

// Preamble prints the preamble for the JSON format.
func (p jsonEventPrinter) Preamble() {}

// Print prints a single event in JSON format with buffered output.
func (p *jsonEventPrinter) Print(event *pb.Event) {
	eBytes, err := event.MarshalJSON()
	if err != nil {
		logger.Errorw("Error marshaling event to json", "error", err)
		return // Don't print empty line on marshal failure
	}

	eBytes = append(eBytes, '\n')
	if _, err := p.buffer.Write(eBytes); err != nil {
		logger.Errorw("Error writing to buffer", "error", err)
		return
	}

	p.eventCount++

	// Flush strategy depends on output destination:
	// - For stdout/stderr: flush immediately for interactive visibility
	// - For files: flush every 10 events OR every 1 second for performance
	shouldFlush := p.isStdoutOrStderr || p.eventCount%10 == 0 || time.Since(p.lastFlush) >= time.Second

	if shouldFlush {
		if err := p.buffer.Flush(); err != nil {
			logger.Errorw("Error flushing buffer", "error", err)
		}
		p.lastFlush = time.Now()
	}
}

// Epilogue prints the epilogue for the JSON format and flushes the buffer.
func (p *jsonEventPrinter) Epilogue(stats metrics.Stats) {
	// Flush buffer when event stream ends to ensure all events are written
	if p.buffer != nil {
		if err := p.buffer.Flush(); err != nil {
			logger.Errorw("Error flushing buffer in epilogue", "error", err)
		}
	}
}

// FromStream receives events from the stream and prints them in JSON format.
func (p *jsonEventPrinter) FromStream(stream *streams.Stream) {
	consumeFromStream(stream, p)
}

// Kind returns the kind of the jsonEventPrinter.
func (p *jsonEventPrinter) Kind() string {
	return "json"
}

// Close closes the jsonEventPrinter and flushes all buffered data.
func (p *jsonEventPrinter) Close() {
	// Flush buffer before syncing to disk
	if p.buffer != nil {
		if err := p.buffer.Flush(); err != nil {
			logger.Errorw("Error flushing buffer on close", "error", err)
		}
	}
	// Sync flushes OS buffers to disk, ensuring events aren't lost on process exit
	if f, ok := p.out.(*os.File); ok {
		_ = f.Sync()
	}
}

// ignoreEventPrinter ignores events and discards all output.
type ignoreEventPrinter struct{}

// Init initializes the ignoreEventPrinter.
func (p *ignoreEventPrinter) Init() error {
	return nil
}

// Preamble prints the preamble for the ignore format (no-op).
func (p *ignoreEventPrinter) Preamble() {}

// Print prints a single event (no-op, events are ignored).
func (p *ignoreEventPrinter) Print(event *pb.Event) {}

// Epilogue prints the epilogue for the ignore format (no-op).
func (p *ignoreEventPrinter) Epilogue(stats metrics.Stats) {}

// FromStream receives events from the stream but ignores them.
func (p *ignoreEventPrinter) FromStream(stream *streams.Stream) {}

// Kind returns the kind of the ignoreEventPrinter.
func (p *ignoreEventPrinter) Kind() string {
	return "ignore"
}

// Close closes the ignoreEventPrinter (no-op).
func (p ignoreEventPrinter) Close() {}

// forwardEventPrinter sends events over the Fluent Forward protocol to a receiver
type forwardEventPrinter struct {
	outPath string
	url     *url.URL
	client  *forward.Client

	// revive:disable:struct-tag

	// These parameters can be set up from the URL
	tag string `default:"tracee"`

	// revive:enable:struct-tag
}

// getParameterValue extracts a parameter value from URL query parameters,
// returning the default value if the parameter is not found or empty.
func getParameterValue(parameters url.Values, key string, defaultValue string) string {
	param, found := parameters[key]
	// Ensure we have a non-empty parameter set for this key
	if found && param[0] != "" {
		return param[0]
	}
	// Otherwise use the default value
	return defaultValue
}

// Init initializes the forwardEventPrinter by parsing the URL and connecting to the Forward destination.
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

// Preamble prints the preamble for the forward format (no-op).
func (p *forwardEventPrinter) Preamble() {}

// Print sends a single event to the Forward destination using the Fluent Forward protocol.
func (p *forwardEventPrinter) Print(event *pb.Event) {
	if p.client == nil {
		logger.Errorw("Invalid Forward client")
		return
	}

	// The actual event is marshalled as JSON then sent with the other information (tag, etc.)
	eBytes, err := event.MarshalJSON()
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

// Epilogue prints the epilogue for the forward format (no-op).
func (p *forwardEventPrinter) Epilogue(stats metrics.Stats) {}

// FromStream receives events from the stream and sends them to the Forward destination.
func (p *forwardEventPrinter) FromStream(stream *streams.Stream) {
	consumeFromStream(stream, p)
}

// Kind returns the kind of the forwardEventPrinter.
func (p *forwardEventPrinter) Kind() string {
	return "forward"
}

// Close closes the forwardEventPrinter and disconnects from the Forward destination.
func (p forwardEventPrinter) Close() {
	if p.client != nil {
		logger.Infow("Disconnecting from Forward destination", "url", p.url.Host, "tag", p.tag)
		if err := p.client.Disconnect(); err != nil {
			logger.Errorw("Disconnecting from Forward destination", "error", err)
		}
	}
}

// webhookEventPrinter sends events to a webhook endpoint via HTTP POST.
type webhookEventPrinter struct {
	outPath     string
	url         *url.URL
	timeout     time.Duration
	format      string
	templateObj *template.Template
	contentType string
}

// Init initializes the webhookEventPrinter by parsing the URL and preparing the template if needed.
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

	if gotemplate, ok := strings.CutPrefix(ws.format, "gotemplate="); ok {
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

// Preamble prints the preamble for the webhook format (no-op).
func (ws *webhookEventPrinter) Preamble() {}

// Print sends a single event to the webhook endpoint via HTTP POST.
func (ws *webhookEventPrinter) Print(event *pb.Event) {
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
		payload, err = event.MarshalJSON()
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

// Epilogue prints the epilogue for the webhook format (no-op).
func (ws *webhookEventPrinter) Epilogue(stats metrics.Stats) {}

// FromStream receives events from the stream and sends them to the webhook endpoint.
func (ws *webhookEventPrinter) FromStream(stream *streams.Stream) {
	consumeFromStream(stream, ws)
}

// Kind returns the kind of the webhookEventPrinter.
func (ws *webhookEventPrinter) Kind() string {
	return "webhook"
}

// Close closes the webhookEventPrinter (no-op).
func (ws *webhookEventPrinter) Close() {}

// consumeFromStream consumes events from a stream and prints them using the provided printer.
// It runs until the stream's event channel is closed, ensuring all events are drained during shutdown.
func consumeFromStream(stream *streams.Stream, printer EventPrinter) {
	for e := range stream.ReceiveEvents() {
		printer.Print(e)
	}
}

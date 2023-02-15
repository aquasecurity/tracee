package printer

import (
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/metrics"
	"github.com/aquasecurity/tracee/types/trace"

	forward "github.com/IBM/fluent-forward-go/fluent/client"
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

type ContainerMode int

const (
	ContainerModeDisabled ContainerMode = iota
	ContainerModeEnabled
	ContainerModeEnriched
)

type Config struct {
	Kind          string
	OutPath       string
	OutFile       io.WriteCloser
	ContainerMode ContainerMode
	RelativeTS    bool
	ForwardURL    *url.URL
}

func New(config Config) (EventPrinter, error) {
	var res EventPrinter
	kind := config.Kind

	if config.OutFile == nil {
		return res, fmt.Errorf("out file is not set")
	}

	switch {
	case kind == "ignore":
		res = &ignoreEventPrinter{}
	case kind == "table":
		res = &tableEventPrinter{
			out:           config.OutFile,
			verbose:       false,
			containerMode: config.ContainerMode,
			relativeTS:    config.RelativeTS,
		}
	case kind == "table-verbose":
		res = &tableEventPrinter{
			out:           config.OutFile,
			verbose:       true,
			containerMode: config.ContainerMode,
			relativeTS:    config.RelativeTS,
		}
	case kind == "json":
		res = &jsonEventPrinter{
			out: config.OutFile,
		}
	case kind == "gob":
		res = &gobEventPrinter{
			out: config.OutFile,
		}
	case kind == "forward":
		res = &forwardEventPrinter{
			url: config.ForwardURL,
		}
	case strings.HasPrefix(kind, "gotemplate="):
		res = &templateEventPrinter{
			out:          config.OutFile,
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
	containerMode ContainerMode
	relativeTS    bool
}

func (p tableEventPrinter) Init() error { return nil }

func (p tableEventPrinter) Preamble() {
	if p.verbose {
		switch p.containerMode {
		case ContainerModeDisabled:
			fmt.Fprintf(p.out,
				"%-16s %-17s %-17s %-13s %-12s %-12s %-6s %-16s %-7s %-7s %-7s %-16s %-20s %s",
				"TIME",
				"SCOPES",
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
		case ContainerModeEnabled:
			fmt.Fprintf(p.out,
				"%-16s %-17s %-17s %-13s %-12s %-12s %-6s %-16s %-15s %-15s %-15s %-16s %-20s %s",
				"TIME",
				"SCOPES",
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
		case ContainerModeEnriched:
			fmt.Fprintf(p.out,
				"%-16s %-17s %-17s %-13s %-16s %-12s %-12s %-6s %-16s %-15s %-15s %-15s %-16s %-20s %s",
				"TIME",
				"SCOPES",
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
		case ContainerModeDisabled:
			fmt.Fprintf(p.out,
				"%-16s %-6s %-16s %-7s %-7s %-16s %-20s %s",
				"TIME",
				"UID",
				"COMM",
				"PID",
				"TID",
				"RET",
				"EVENT",
				"ARGS",
			)
		case ContainerModeEnabled:
			fmt.Fprintf(p.out,
				"%-16s %-13s %-6s %-16s %-15s %-15s %-16s %-20s %s",
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
		case ContainerModeEnriched:
			fmt.Fprintf(p.out,
				"%-16s %-13s %-16s %-6s %-16s %-15s %-15s %-16s %-20s %s",
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

	containerId := event.ContainerID
	if len(containerId) > 12 {
		containerId = containerId[:12]
	}
	containerImage := event.ContainerImage
	if len(containerImage) > 16 {
		containerImage = containerImage[:16]
	}

	eventName := event.EventName
	if len(eventName) > 20 {
		eventName = eventName[:17] + "..."
	}

	if p.verbose {
		switch p.containerMode {
		case ContainerModeDisabled:
			fmt.Fprintf(p.out,
				"%-16s %016x  %-16s %-13s %-12d %-12d %-6d %-16s %-7d %-7d %-7d %-16d %-20s ",
				timestamp,
				event.MatchedScopes,
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
		case ContainerModeEnabled:
			fmt.Fprintf(p.out,
				"%-16s %016x  %-16s %-13s %-12d %-12d %-6d %-16s %-7d/%-7d %-7d/%-7d %-7d/%-7d %-16d %-20s ",
				timestamp,
				event.MatchedScopes,
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
		case ContainerModeEnriched:
			fmt.Fprintf(p.out,
				"%-16s %016x  %-16s %-13s %-16s %-12d %-12d %-6d %-16s %-7d/%-7d %-7d/%-7d %-7d/%-7d %-16d %-20s ",
				timestamp,
				event.MatchedScopes,
				event.HostName,
				containerId,
				event.ContainerImage,
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
		case ContainerModeDisabled:
			fmt.Fprintf(p.out,
				"%-16s %-6d %-16s %-7d %-7d %-16d %-20s ",
				timestamp,
				event.UserID,
				event.ProcessName,
				event.ProcessID,
				event.ThreadID,
				event.ReturnValue,
				eventName,
			)
		case ContainerModeEnabled:
			fmt.Fprintf(p.out,
				"%-16s %-13s %-6d %-16s %-7d/%-7d %-7d/%-7d %-16d %-20s ",
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
		case ContainerModeEnriched:
			fmt.Fprintf(p.out,
				"%-16s %-13s %-16s %-6d %-16s %-7d/%-7d %-7d/%-7d %-16d %-20s ",
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
		if i == 0 {
			fmt.Fprintf(p.out, "%s: %v", arg.Name, arg.Value)
		} else {
			fmt.Fprintf(p.out, ", %s: %v", arg.Name, arg.Value)
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
	if tmplPath != "" {
		tmpl, err := template.ParseFiles(tmplPath)
		if err != nil {
			return err
		}
		p.templateObj = &tmpl
	} else {
		return errors.New("please specify a gotemplate for event-based output")
	}
	return nil
}

func (p templateEventPrinter) Preamble() {}

func (p templateEventPrinter) Print(event trace.Event) {
	if p.templateObj != nil {
		err := (*p.templateObj).Execute(p.out, event)
		if err != nil {
			logger.Error("error executing template", "error", err)
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
		logger.Error("error marshaling event to json", "error", err)
	}
	fmt.Fprintln(p.out, string(eBytes))
}

func (p jsonEventPrinter) Epilogue(stats metrics.Stats) {}

func (p jsonEventPrinter) Close() {
}

// gobEventPrinter is printing events using golang's builtin Gob serializer
type gobEventPrinter struct {
	out    io.WriteCloser
	outEnc *gob.Encoder
}

func (p *gobEventPrinter) Init() error {
	p.outEnc = gob.NewEncoder(p.out)

	// Event Types

	gob.Register(trace.Event{})
	gob.Register(trace.SlimCred{})
	gob.Register(make(map[string]string))
	gob.Register(trace.PktMeta{})
	gob.Register([]trace.HookedSymbolData{})
	gob.Register(map[string]trace.HookedSymbolData{})
	gob.Register([]trace.DnsQueryData{})
	gob.Register([]trace.DnsResponseData{})

	// Network Protocol Event Types

	// IPv4
	gob.Register(trace.ProtoIPv4{})
	// IPv6
	gob.Register(trace.ProtoIPv6{})
	// TCP
	gob.Register(trace.ProtoTCP{})
	// UDP
	gob.Register(trace.ProtoUDP{})
	// ICMP
	gob.Register(trace.ProtoICMP{})
	// ICMPv6
	gob.Register(trace.ProtoICMPv6{})
	// DNS
	gob.Register(trace.ProtoDNS{})
	gob.Register(trace.ProtoDNSQuestion{})
	gob.Register(trace.ProtoDNSResourceRecord{})
	gob.Register(trace.ProtoDNSSOA{})
	gob.Register(trace.ProtoDNSSRV{})
	gob.Register(trace.ProtoDNSMX{})
	gob.Register(trace.ProtoDNSURI{})
	gob.Register(trace.ProtoDNSOPT{})
	// HTTP
	gob.Register(trace.ProtoHTTP{})
	gob.Register(trace.ProtoHTTPRequest{})
	gob.Register(trace.ProtoHTTPResponse{})

	return nil
}

func (p *gobEventPrinter) Preamble() {}

func (p *gobEventPrinter) Print(event trace.Event) {
	err := p.outEnc.Encode(event)
	if err != nil {
		logger.Error("error encoding event to gob", "error", err)
	}
}

func (p *gobEventPrinter) Epilogue(stats metrics.Stats) {}

func (p gobEventPrinter) Close() {
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
	url    *url.URL
	client *forward.Client
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
	parameters, _ := url.ParseQuery(p.url.RawQuery)

	// Check if we have a tag set or default it
	p.tag = getParameterValue(parameters, "tag", "tracee")

	// Do we want to enable requireAck?
	requireAckString := getParameterValue(parameters, "requireAck", "false")
	requireAck, err := strconv.ParseBool(requireAckString)
	if err != nil {
		return fmt.Errorf("unable to convert requireAck value %q: %w", requireAckString, err)
	}

	// Timeout conversion from string
	timeoutValueString := getParameterValue(parameters, "connectionTimeout", "10s")
	connectionTimeout, err := time.ParseDuration(timeoutValueString)
	if err != nil {
		return fmt.Errorf("unable to convert connectionTimeout value %q: %w", timeoutValueString, err)
	}

	// We should have both username and password or neither for basic auth
	username := p.url.User.Username()
	password, isPasswordSet := p.url.User.Password()
	if username != "" && !isPasswordSet {
		return fmt.Errorf("missing basic auth configuration for Forward destination")
	}

	// Ensure we support tcp or udp protocols
	protocol := "tcp"
	if p.url.Scheme != "" {
		protocol = p.url.Scheme
	}
	if protocol != "tcp" && protocol != "udp" {
		return fmt.Errorf("unsupported protocol for Forward destination: %s", protocol)
	}

	// Extract the host (and port)
	address := p.url.Host
	logger.Info("attempting to connect to Forward destination", "url", address, "tag", p.tag)

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
		logger.Error("error connecting to Forward destination", "url", p.url.String(), "error", err)
	}
	return nil
}

func (p *forwardEventPrinter) Preamble() {}

func (p *forwardEventPrinter) Print(event trace.Event) {
	if p.client == nil {
		logger.Error("invalid Forward client")
		return
	}

	// The actual event is marshalled as JSON then sent with the other information (tag, etc.)
	eBytes, err := json.Marshal(event)
	if err != nil {
		logger.Error("error marshaling event to json", "error", err)
	}

	record := map[string]interface{}{
		"event": string(eBytes),
	}

	err = p.client.SendMessage(p.tag, record)
	// Assuming all is well we continue but if the connection is dropped or some other error we retry
	if err != nil {
		logger.Error("error writing to Forward destination", "destination", p.url.Host, "tag", p.tag, "error", err)
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
		logger.Info("disconnecting from Forward destination", "url", p.url.Host, "tag", p.tag)
		p.client.Disconnect()
	}
}

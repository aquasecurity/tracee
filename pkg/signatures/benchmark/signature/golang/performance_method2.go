package golang

import (
	"fmt"
	"regexp"

	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type performanceMethod2 struct {
	processMemFileRegexp *regexp.Regexp
	cb                   detect.SignatureHandler
}

var performanceMethod2Regexp = regexp.MustCompile(`^/proc/(?:\d+|self)/mem$`)

var performanceMethod2Metadata = detect.SignatureMetadata{
	Name:        "Code injection",
	EventName:   "test_event_name",
	Description: "Possible process injection detected during runtime",
	Tags:        []string{"linux", "container"},
	Properties: map[string]interface{}{
		"Severity":     3,
		"MITRE ATT&CK": "Defense Evasion: Process Injection",
	},
}

func NewperformanceMethod2() (detect.Signature, error) {
	return &performanceMethod2{
		processMemFileRegexp: performanceMethod2Regexp,
	}, nil
}

func (sig *performanceMethod2) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback

	return nil
}

func (sig *performanceMethod2) GetMetadata() (detect.SignatureMetadata, error) {
	return performanceMethod2Metadata, nil
}

func (sig *performanceMethod2) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "ptrace"},
		{Source: "tracee", Name: "open"},
		{Source: "tracee", Name: "openat"},
		{Source: "tracee", Name: "execve"},
	}, nil
}

func (sig *performanceMethod2) OnEvent(event protocol.Event) error {
	// event example:
	// { "eventName": "ptrace", "args": [{"name": "request", "value": "PTRACE_POKETEXT" }]}
	// { "eventName": "open", "args": [{"name": "flags", "value": "o_wronly" }, {"name": "pathname", "value": "/proc/self/mem" }]}
	// { "eventName": "execve" args": [{"name": "envp", "value": ["FOO=BAR", "LD_PRELOAD=/something"] }, {"name": "argv", "value": ["ls"] }]}
	ee, ok := event.Payload.(trace.Event)

	if !ok {
		return fmt.Errorf("failed to cast event's payload")
	}
	switch ee.EventName {
	case "open", "openat":
		flags, err := helpers.GetTraceeArgumentByName(ee, "flags", helpers.GetArgOps{DefaultArgs: false})
		if err != nil {
			return fmt.Errorf("%v %#v", err, ee)
		}
		if helpers.IsFileWrite(flags.Value.(string)) {
			pathname, err := helpers.GetTraceeArgumentByName(ee, "pathname", helpers.GetArgOps{DefaultArgs: false})
			if err != nil {
				return err
			}
			if sig.processMemFileRegexp.MatchString(pathname.Value.(string)) {
				metadata, err := sig.GetMetadata()
				if err != nil {
					return err
				}
				sig.cb(&detect.Finding{
					SigMetadata: metadata,
					Event:       event,
					Data: map[string]interface{}{
						"file flags": flags,
						"file path":  pathname.Value.(string),
					},
				})
			}
		}
	case "ptrace":
		request, err := helpers.GetTraceeArgumentByName(ee, "request", helpers.GetArgOps{DefaultArgs: false})
		if err != nil {
			return err
		}

		requestString, ok := request.Value.(string)
		if !ok {
			return fmt.Errorf("failed to cast request's value")
		}

		if requestString == "PTRACE_POKETEXT" || requestString == "PTRACE_POKEDATA" {
			metadata, err := sig.GetMetadata()
			if err != nil {
				return err
			}
			sig.cb(&detect.Finding{
				SigMetadata: metadata,
				Event:       event,
				Data: map[string]interface{}{
					"ptrace request": requestString,
				},
			})
		}
	}
	return nil
}

func (sig *performanceMethod2) OnSignal(s detect.Signal) error {
	return nil
}
func (sig *performanceMethod2) Close() {}

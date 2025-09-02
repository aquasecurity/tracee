package golang

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/aquasecurity/tracee/common/parsers"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type codeInjection struct {
	processMemFileRegexp *regexp.Regexp
	cb                   detect.SignatureHandler
	metadata             detect.SignatureMetadata
}

func NewCodeInjectionSignature() (detect.Signature, error) {
	processMemFileRegexp, err := regexp.Compile(`/proc/(?:\d.+|self)/mem`)
	if err != nil {
		return nil, err
	}
	return &codeInjection{
		processMemFileRegexp: processMemFileRegexp,
		metadata: detect.SignatureMetadata{
			Name:        "Code injection",
			Description: "Possible process injection detected during runtime",
			Tags:        []string{"linux", "container"},
			Properties: map[string]interface{}{
				"Severity":     3,
				"MITRE ATT&CK": "Defense Evasion: Process Injection",
			},
		},
	}, nil
}

func (sig *codeInjection) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *codeInjection) GetMetadata() (detect.SignatureMetadata, error) {
	return sig.metadata, nil
}

func (sig *codeInjection) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "ptrace"},
		{Source: "tracee", Name: "open"},
		{Source: "tracee", Name: "openat"},
		{Source: "tracee", Name: "execve"},
	}, nil
}

func (sig *codeInjection) OnEvent(event protocol.Event) error {
	// event example:
	// { "eventName": "ptrace", "args": [{"name": "request", "value": "PTRACE_POKETEXT" }]}
	// { "eventName": "open", "args": [{"name": "flags", "value": "o_wronly" }, {"name": "pathname", "value": "/proc/self/mem" }]}
	// { "eventName": "execve" args": [{"name": "envp", "value": ["FOO=BAR", "LD_PRELOAD=/something"] }, {"name": "argv", "value": ["ls"] }]}
	ee, ok := event.Payload.(trace.Event)

	if !ok {
		return errors.New("failed to cast event's payload")
	}
	switch ee.EventName {
	case "open", "openat":
		flags, err := ee.GetIntArgumentByName("flags")
		if err != nil {
			return fmt.Errorf("%v %#v", err, ee)
		}
		if parsers.IsFileWrite(flags) {
			pathname, err := ee.GetArgumentByName("pathname", trace.GetArgOps{DefaultArgs: false})
			if err != nil {
				return err
			}
			if sig.processMemFileRegexp.MatchString(pathname.Value.(string)) {
				sig.cb(&detect.Finding{
					// Signature: sig,
					SigMetadata: sig.metadata,
					Event:       event,
					Data: map[string]interface{}{
						"file flags": flags,
						"file path":  pathname.Value.(string),
					},
				})
			}
		}
	case "ptrace":
		request, err := ee.GetArgumentByName("request", trace.GetArgOps{DefaultArgs: false})
		if err != nil {
			return err
		}

		requestString, ok := request.Value.(string)
		if !ok {
			return errors.New("failed to cast request's value")
		}

		if requestString == "PTRACE_POKETEXT" || requestString == "PTRACE_POKEDATA" {
			sig.cb(&detect.Finding{
				// Signature: sig,
				SigMetadata: sig.metadata,
				Event:       event,
				Data: map[string]interface{}{
					"ptrace request": requestString,
				},
			})
		}
		// TODO Commenting out the execve case to make it equivalent to Rego signature
		//
		// case "execve":
		//	envs, err := ee.GetArgumentByName("envp", trace.GetArgOps{DefaultArgs: false})
		//	if err != nil {
		//		break
		//	}
		//	envsSlice := envs.Value.([]string)
		//	for _, env := range envsSlice {
		//		if strings.HasPrefix(env, "LD_PRELOAD") || strings.HasPrefix(env, "LD_LIBRARY_PATH") {
		//			cmd, err := ee.GetArgumentByName("argv", trace.GetArgOps{DefaultArgs: false})
		//			if err != nil {
		//				return err
		//			}
		//			sig.cb(&detect.Finding{
		// Signature: sig,
		//				SigMetadata: sig.metadata,
		//				Payload:     ee,
		//				Data: map[string]interface{}{
		//					"command":     cmd,
		//					"command env": env,
		//				},
		//			})
		//		}
		//	}
	}
	return nil
}

func (sig *codeInjection) OnSignal(s detect.Signal) error {
	return nil
}
func (sig *codeInjection) Close() {}

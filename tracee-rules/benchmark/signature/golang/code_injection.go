package golang

import (
	"fmt"
	"regexp"

	tracee "github.com/aquasecurity/tracee/pkg/external"
	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

type codeInjection struct {
	processMemFileRegexp *regexp.Regexp
	cb                   types.SignatureHandler
	metadata             types.SignatureMetadata
}

func NewCodeInjectionSignature() (types.Signature, error) {
	processMemFileRegexp, err := regexp.Compile(`/proc/(?:\d.+|self)/mem`)
	if err != nil {
		return nil, err
	}
	return &codeInjection{
		processMemFileRegexp: processMemFileRegexp,
		metadata: types.SignatureMetadata{
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

func (sig *codeInjection) Init(cb types.SignatureHandler) error {
	sig.cb = cb
	return nil
}

func (sig *codeInjection) GetMetadata() (types.SignatureMetadata, error) {
	return sig.metadata, nil
}

func (sig *codeInjection) GetSelectedEvents() ([]types.SignatureEventSelector, error) {
	return []types.SignatureEventSelector{
		{Source: "tracee", Name: "ptrace"},
		{Source: "tracee", Name: "open"},
		{Source: "tracee", Name: "openat"},
		{Source: "tracee", Name: "execve"},
	}, nil
}

func (sig *codeInjection) OnEvent(e types.Event) error {
	// event example:
	// { "eventName": "ptrace", "args": [{"name": "request", "value": "PTRACE_POKETEXT" }]}
	// { "eventName": "open", "args": [{"name": "flags", "value": "o_wronly" }, {"name": "pathname", "value": "/proc/self/mem" }]}
	// { "eventName": "execve" args": [{"name": "envp", "value": ["FOO=BAR", "LD_PRELOAD=/something"] }, {"name": "argv", "value": ["ls"] }]}
	ee, ok := e.(tracee.Event)
	if !ok {
		return fmt.Errorf("invalid event")
	}
	switch ee.EventName {
	case "open", "openat":
		flags, err := helpers.GetTraceeArgumentByName(ee, "flags")
		if err != nil {
			return fmt.Errorf("%v %#v", err, ee)
		}
		if helpers.IsFileWrite(flags.Value.(string)) {
			pathname, err := helpers.GetTraceeArgumentByName(ee, "pathname")
			if err != nil {
				return err
			}
			if sig.processMemFileRegexp.MatchString(pathname.Value.(string)) {
				sig.cb(types.Finding{
					//Signature: sig,
					SigMetadata: sig.metadata,
					Context:     ee,
					Data: map[string]interface{}{
						"file flags": flags,
						"file path":  pathname.Value.(string),
					},
				})
			}
		}
	case "ptrace":
		request, err := helpers.GetTraceeArgumentByName(ee, "request")
		if err != nil {
			return err
		}
		requestString := request.Value.(string)
		if requestString == "PTRACE_POKETEXT" || requestString == "PTRACE_POKEDATA" {
			sig.cb(types.Finding{
				//Signature: sig,
				SigMetadata: sig.metadata,
				Context:     ee,
				Data: map[string]interface{}{
					"ptrace request": requestString,
				},
			})
		}
		// TODO Commenting out the execve case to make it equivalent to Rego signature
		//case "execve":
		//	envs, err := helpers.GetTraceeArgumentByName(ee, "envp")
		//	if err != nil {
		//		break
		//	}
		//	envsSlice := envs.Value.([]string)
		//	for _, env := range envsSlice {
		//		if strings.HasPrefix(env, "LD_PRELOAD") || strings.HasPrefix(env, "LD_LIBRARY_PATH") {
		//			cmd, err := helpers.GetTraceeArgumentByName(ee, "argv")
		//			if err != nil {
		//				return err
		//			}
		//			sig.cb(types.Finding{
		//				//Signature: sig,
		//				SigMetadata: sig.metadata,
		//				Context:     ee,
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

func (sig *codeInjection) OnSignal(s types.Signal) error {
	return nil
}
func (sig *codeInjection) Close() {}

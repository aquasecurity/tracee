package celsig_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/signatures/celsig"
	"github.com/aquasecurity/tracee/signatures/signaturestest"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestSignature_GetSelectedEvents(t *testing.T) {
	signature, err := celsig.NewSignature(celsig.SignatureConfig{
		Metadata: detect.SignatureMetadata{
			ID:   "TRC-2",
			Name: "Anti-Debugging",
		},
		EventSelectors: []detect.SignatureEventSelector{
			{
				Origin: "tracee",
				Name:   "ptrace",
			},
		},
		Expression: `input.eventName == 'ptrace' && input.stringArg('request') == 'PTRACE_TRACEME'`,
	})
	require.NoError(t, err)
	selectedEvents, err := signature.GetSelectedEvents()
	require.NoError(t, err)
	assert.Equal(t, []detect.SignatureEventSelector{
		{
			Origin: "tracee",
			Name:   "ptrace",
		},
	}, selectedEvents)
}

func TestSignature_OnEvent(t *testing.T) {
	testCases := []struct {
		name    string
		config  celsig.SignatureConfig
		input   protocol.Event
		finding *detect.Finding
	}{
		{
			name: "Should trigger finding when string arg matches expression",
			config: celsig.SignatureConfig{
				Metadata: detect.SignatureMetadata{
					ID:   "TRC-2",
					Name: "Anti-Debugging",
				},
				Expression: `input.eventName == 'ptrace' && input.stringArg('request') == 'PTRACE_TRACEME'`,
			},
			input: protocol.Event{
				Payload: trace.Event{
					EventName: "ptrace",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Type: "string",
								Name: "request",
							},
							Value: "PTRACE_TRACEME",
						},
					},
				},
			},
			finding: &detect.Finding{
				SigMetadata: detect.SignatureMetadata{
					ID:   "TRC-2",
					Name: "Anti-Debugging",
				},
				Event: protocol.Event{
					Headers: protocol.EventHeaders{},
					Payload: trace.Event{
						EventName: "ptrace",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Type: "string",
									Name: "request",
								},
								Value: "PTRACE_TRACEME",
							},
						},
					},
				},
			},
		},
		{
			name: "Should trigger finding when sockaddr arg matches expression",
			config: celsig.SignatureConfig{
				Metadata: detect.SignatureMetadata{
					ID:      "CEL-TEST-SOCKET-ADDR-ARGS",
					Version: "0.1.0",
					Name:    "Test sockaddr Args",
				},
				Expression: `input.eventName == 'connect' &&
input.sockaddrArg('addr') == wrapper.sockaddr{
  sa_family: wrapper.sa_family_t.AF_INET,
  sin_addr: '216.58.215.110',
  sin_port: 80u
}
`,
			},
			input: protocol.Event{
				Payload: trace.Event{
					EventName: "connect",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "addr",
								Type: "struct sockaddr*",
							},
							Value: map[string]string{
								"sa_family": "AF_INET",
								"sin_addr":  "216.58.215.110",
								"sin_port":  "80",
							},
						},
					},
				},
			},
			finding: &detect.Finding{
				SigMetadata: detect.SignatureMetadata{
					ID:      "CEL-TEST-SOCKET-ADDR-ARGS",
					Version: "0.1.0",
					Name:    "Test sockaddr Args",
				},
				Event: protocol.Event{
					Payload: trace.Event{
						EventName: "connect",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "addr",
									Type: "struct sockaddr*",
								},
								Value: map[string]string{
									"sa_family": "AF_INET",
									"sin_addr":  "216.58.215.110",
									"sin_port":  "80",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Should not trigger finding when nested string arg is undefined",
			config: celsig.SignatureConfig{
				Metadata: detect.SignatureMetadata{
					ID:      "CEL-TEST-SOCKET-ADDR-ARGS",
					Version: "0.1.0",
					Name:    "Test SocketAddr Args",
				},
				Expression: `input.eventName == 'connect' &&
input.sockaddrArg('addr').sin_addr == "216.58.215.110"`,
			},
			input: protocol.Event{
				Payload: trace.Event{
					EventName: "connect",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "addr",
								Type: "struct sockaddr*",
							},
							Value: map[string]string{},
						},
					},
				},
			},
			finding: nil,
		},
		{
			name: "Should not trigger finding when sockaddr arg is undefined",
			config: celsig.SignatureConfig{
				Metadata: detect.SignatureMetadata{
					ID:      "CEL-TEST-SOCKET-ADDR-ARGS",
					Version: "0.1.0",
					Name:    "Test SocketAddr Args",
				},
				Expression: `input.eventName == 'connect' &&
input.sockaddrArg('addr').sin_addr == "216.58.215.110"`,
			},
			input: protocol.Event{
				Payload: trace.Event{
					EventName: "connect",
					Args: []trace.Argument{
						{},
					},
				},
			},
			finding: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			signature, err := celsig.NewSignature(tc.config)
			require.NoError(t, err)
			holder := &signaturestest.FindingsHolder{}
			err = signature.Init(detect.SignatureContext{Callback: holder.OnFinding})
			require.NoError(t, err)
			err = signature.OnEvent(tc.input)
			require.NoError(t, err)
			assert.Equal(t, tc.finding, holder.FirstValue())
		})
	}

}

// go test -run=XXX -bench=. -benchmem -cpu=1
func BenchmarkSignature_OnEvent(b *testing.B) {
	benchmarks := []struct {
		config celsig.SignatureConfig
		input  protocol.Event
	}{
		{
			config: celsig.SignatureConfig{
				Metadata: detect.SignatureMetadata{
					Name: "Anti-Debugging",
				},
				Expression: `input.eventName == 'ptrace' && input.stringArg('request') == 'PTRACE_TRACEME'`,
			},
			input: protocol.Event{
				Payload: trace.Event{
					EventName: "ptrace",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Type: "string",
								Name: "request",
							},
							Value: "PTRACE_TRACEME",
						},
					},
				},
			},
		},
		{
			config: celsig.SignatureConfig{
				Metadata: detect.SignatureMetadata{
					Name: "Illegitimate Shell",
				},
				Expression: `input.eventName == 'security_bprm_check' &&
input.processName in ['nginx', 'httpd', 'httpd-foregroun', 'lighttpd', 'apache', 'apache2'] &&
['/ash', '/bash', '/csh', '/ksh', '/sh', '/tcsh', '/zsh', '/dash'].exists(e, input.stringArg('pathname').endsWith(e))`,
			},
			input: protocol.Event{
				Payload: trace.Event{
					EventName:   "security_bprm_check",
					ProcessName: "nginx",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Type: "string",
								Name: "pathname",
							},
							Value: "/bin/dash",
						},
					},
				},
			},
		},
		{
			config: celsig.SignatureConfig{
				Metadata: detect.SignatureMetadata{
					Name: "Fileless Execution",
				},
				Expression: `(
        input.eventName == 'sched_process_exec' &&
        input.stringArg('pathname').startsWith('memfd:') &&
        input.containerID == '' &&
        !input.stringArg('pathname').startsWith('memfd:runc')
      ) ||
      (
        input.eventName == 'sched_process_exec' &&
        input.containerID != '' &&
        input.stringArg('pathname').startsWith('memfd:')
      ) ||
      (
        input.eventName == 'sched_process_exec' &&
        input.stringArg('pathname').startsWith('/dev/shm')
      ) ||
      (
        input.eventName == 'sched_process_exec' &&
        input.stringArg('pathname').startsWith('/run/shm')
      )`,
			},
			input: protocol.Event{
				Payload: trace.Event{
					EventName: "sched_process_exec",
					ArgsNum:   1,
					Container: trace.Container{ID: "someContainer"},
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Type: "string",
								Name: "pathname",
							},
							Value: "memfd://something/something",
						},
					},
				},
			},
		},
		{
			config: celsig.SignatureConfig{
				Metadata: detect.SignatureMetadata{
					Name: "SockAddr",
				},
				Expression: `input.eventName == 'connect' &&
input.sockaddrArg('addr') == wrapper.sockaddr{
  sa_family: wrapper.sa_family_t.AF_INET,
  sin_addr: '216.58.209.14',
  sin_port: 80u
}`,
			},
			input: protocol.Event{
				Payload: trace.Event{
					EventName: "connect",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "addr",
								Type: "struct sockaddr*",
							},
							Value: map[string]string{
								"sa_family": "AF_INET",
								"sin_addr":  "216.58.209.14",
								"sin_port":  "80",
							},
						},
					},
				},
			},
		},
	}
	for _, bm := range benchmarks {
		b.Run(bm.config.Metadata.Name, func(b *testing.B) {
			signature, err := celsig.NewSignature(bm.config)
			require.NoError(b, err)
			holder := &signaturestest.FindingsHolder{}
			err = signature.Init(detect.SignatureContext{Callback: holder.OnFinding})
			require.NoError(b, err)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				err = signature.OnEvent(bm.input)
				require.NoError(b, err)
			}
		})
	}
}

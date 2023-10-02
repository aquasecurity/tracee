package regosig_test

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/open-policy-agent/opa/compile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/signatures/regosig"
	"github.com/aquasecurity/tracee/signatures/signaturestest"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestRegoSignature_GetMetadata(t *testing.T) {
	t.Parallel()

	sig, err := regosig.NewRegoSignature(compile.TargetRego, false, testRegoCodeBoolean)
	require.NoError(t, err)

	metadata, err := sig.GetMetadata()
	require.NoError(t, err)
	assert.Equal(t, detect.SignatureMetadata{
		ID:          "TRC-BOOL",
		Version:     "0.1.0",
		Name:        "test name",
		Description: "test description",
		Tags: []string{
			"tag1",
			"tag2",
		},
		Properties: map[string]interface{}{
			"p1": "test",
			"p2": json.Number("1"),
			"p3": true,
		},
	}, metadata)
}

func TestRegoSignature_GetSelectedEvents(t *testing.T) {
	t.Parallel()

	sig, err := regosig.NewRegoSignature(compile.TargetRego, false, testRegoCodeBoolean)
	require.NoError(t, err)
	events, err := sig.GetSelectedEvents()
	require.NoError(t, err)
	assert.Equal(t, []detect.SignatureEventSelector{
		{
			Source: "tracee",
			Name:   "execve",
		},
	}, events)
}

func TestRegoSignature_OnEvent(t *testing.T) {
	t.Parallel()

	options := []struct {
		target  string
		partial bool
	}{
		{
			target:  compile.TargetRego,
			partial: false,
		},
		{
			target:  compile.TargetRego,
			partial: true,
		},
		//{
		//	target:  compile.TargetWasm,
		//	partial: false,
		//},
		//{
		//	target:  compile.TargetWasm,
		//	partial: true,
		//},
	}

	for _, tc := range options {
		tc := tc

		t.Run(fmt.Sprintf("target=%s,partial=%t", tc.target, tc.partial), func(t *testing.T) {
			t.Parallel()

			OnEventSpec(t, tc.target, tc.partial)
		})
	}

}

// OnEventSpec describes the behavior of RegoSignature.OnEvent.
func OnEventSpec(t *testing.T, target string, partial bool) {
	testCases := []struct {
		name     string
		regoCode string
		event    protocol.Event

		finding *detect.Finding
		error   string
	}{
		{
			name:     "Should trigger finding when tracee_match rule returns boolean and event matches",
			regoCode: testRegoCodeBoolean,
			event: trace.Event{
				Args: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "doesn't matter",
						},
						Value: "ends with yo",
					},
				},
			}.ToProtocol(),
			finding: &detect.Finding{
				Data: nil,
				Event: trace.Event{
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "doesn't matter",
							},
							Value: "ends with yo",
						},
					},
				}.ToProtocol(),
				SigMetadata: detect.SignatureMetadata{
					ID:          "TRC-BOOL",
					Version:     "0.1.0",
					Name:        "test name",
					Description: "test description",
					Tags: []string{
						"tag1",
						"tag2",
					},
					Properties: map[string]interface{}{
						"p1": "test",
						"p2": json.Number("1"),
						"p3": true,
					},
				},
			},
		},
		{
			name:     "Should trigger finding when tracee_match rule returns boolean and parsed event matches",
			regoCode: testRegoCodeBoolean,
			event: trace.Event{
				Args: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "doesn't matter",
						},
						Value: "ends with yo",
					},
				},
			}.ToProtocol(),
			finding: &detect.Finding{
				Data: nil,
				Event: trace.Event{
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "doesn't matter",
							},
							Value: "ends with yo",
						},
					},
				}.ToProtocol(),
				SigMetadata: detect.SignatureMetadata{
					ID:          "TRC-BOOL",
					Version:     "0.1.0",
					Name:        "test name",
					Description: "test description",
					Tags: []string{
						"tag1",
						"tag2",
					},
					Properties: map[string]interface{}{
						"p1": "test",
						"p2": json.Number("1"),
						"p3": true,
					},
				},
			},
		},
		{
			name:     "Shouldn't trigger finding when tracee_match rule returns boolean but event doesn't match",
			regoCode: testRegoCodeBoolean,
			event: trace.Event{
				Args: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "doesn't matter",
						},
						Value: "doesn't end with yo!",
					},
				},
			}.ToProtocol(),
			finding: nil,
		},
		{
			name:     "Should trigger finding when tracee_match rule returns object and event matches",
			regoCode: testRegoCodeObject,
			event: trace.Event{
				Args: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "doesn't matter",
						},
						Value: "ends with yo",
					},
					{
						ArgMeta: trace.ArgMeta{
							Name: "doesn't matter",
						},
						Value: 1337,
					},
				},
			}.ToProtocol(),
			finding: &detect.Finding{
				Data: map[string]interface{}{
					"p1": "test",
					"p2": json.Number("1"),
					"p3": true,
				},
				Event: trace.Event{
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "doesn't matter",
							},
							Value: "ends with yo",
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "doesn't matter",
							},
							Value: 1337,
						},
					},
				}.ToProtocol(),
				SigMetadata: detect.SignatureMetadata{
					ID:          "TRC-OBJECT",
					Version:     "0.3.0",
					Name:        "test name",
					Description: "test description",
					Tags: []string{
						"tag1",
						"tag2",
					},
					Properties: map[string]interface{}{
						"p1": "test",
						"p2": json.Number("1"),
						"p3": true,
					},
				},
			},
		},
		{
			name:     "Should trigger finding when tracee_match rule returns object and parsed event matches",
			regoCode: testRegoCodeObject,
			event: trace.Event{
				Args: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "doesn't matter",
						},
						Value: "ends with yo",
					},
					{
						ArgMeta: trace.ArgMeta{
							Name: "doesn't matter",
						},
						Value: 1337,
					},
				},
			}.ToProtocol(),
			finding: &detect.Finding{
				Data: map[string]interface{}{
					"p1": "test",
					"p2": json.Number("1"),
					"p3": true,
				},
				Event: trace.Event{
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "doesn't matter",
							},
							Value: "ends with yo",
						},
						{
							ArgMeta: trace.ArgMeta{
								Name: "doesn't matter",
							},
							Value: 1337,
						},
					},
				}.ToProtocol(),
				SigMetadata: detect.SignatureMetadata{
					ID:          "TRC-OBJECT",
					Version:     "0.3.0",
					Name:        "test name",
					Description: "test description",
					Tags: []string{
						"tag1",
						"tag2",
					},
					Properties: map[string]interface{}{
						"p1": "test",
						"p2": json.Number("1"),
						"p3": true,
					},
				},
			},
		},
		{
			name:     "Shouldn't trigger finding when tracee_match rule returns object but event doesn't match",
			regoCode: testRegoCodeObject,
			event: trace.Event{
				Args: []trace.Argument{
					{
						ArgMeta: trace.ArgMeta{
							Name: "doesn't matter",
						},
						Value: "yo is not at end",
					},
				},
			}.ToProtocol(),
			finding: nil,
		},
		{
			name:     "No finding because payload is irrelevant",
			regoCode: testRegoCodeObject,
			event: protocol.Event{
				Headers: protocol.EventHeaders{
					Selector: protocol.Selector{
						Name:   "joke",
						Origin: "nowhere",
						Source: "system",
					},
				},
				Payload: "just some stuff",
			},
			finding: nil,
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sig, err := regosig.NewRegoSignature(target, partial, tc.regoCode)
			require.NoError(t, err)

			holder := &signaturestest.FindingsHolder{}
			err = sig.Init(detect.SignatureContext{Callback: holder.OnFinding})
			require.NoError(t, err)

			event := tc.event
			err = sig.OnEvent(event)
			if tc.error != "" {
				assert.EqualError(t, err, tc.error)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.finding, holder.FirstValue())
			}
		})
	}
}

func TestRegoSignature_OnSignal(t *testing.T) {
	t.Parallel()

	sig, err := regosig.NewRegoSignature(compile.TargetRego, false, testRegoCodeBoolean)
	require.NoError(t, err)
	err = sig.OnSignal(os.Kill)
	assert.EqualError(t, err, "function OnSignal is not implemented")
}

var (
	//go:embed testdata/anti_debugging_ptraceme.rego
	antiDebuggingSignature string

	//go:embed testdata/illegitimate_shell.rego
	illegitimateShell string

	//go:embed testdata/fileless_execution.rego
	filelessExecution string

	//go:embed testdata/sockaddr.rego
	sockaddr string

	//go:embed testdata/helpers.rego
	helpers string
)

// go test -run=XXX -bench=. -benchmem -cpu=1
func BenchmarkSignature_OnEvent(b *testing.B) {
	benchmarks := []struct {
		name      string
		regoCodes []string
		input     protocol.Event
	}{
		{
			name: "Anti-Debugging",
			regoCodes: []string{
				antiDebuggingSignature,
			},
			input: protocol.Event{
				Payload: trace.Event{
					EventName: "ptrace",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "request",
							},
							Value: "PTRACE_TRACEME",
						},
					},
				},
			},
		},
		{
			name: "Illegitimate Shell",
			regoCodes: []string{
				helpers,
				illegitimateShell,
			},
			input: protocol.Event{
				Payload: trace.Event{
					EventName: "security_bprm_check",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "pathname",
							},
							Value: "/bin/dash",
						},
					},
				},
			},
		},
		{
			name: "Fileless Execution",
			regoCodes: []string{
				helpers,
				filelessExecution,
			},
			input: protocol.Event{
				Payload: trace.Event{
					EventName: "sched_process_exec",
					ArgsNum:   1,
					Container: trace.Container{ID: "someContainer"},
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "pathname",
							},
							Value: "memfd://something/something",
						},
					},
				},
			},
		},
		{
			name: "SockAddr",
			regoCodes: []string{
				helpers,
				sockaddr,
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
		b.Run(bm.name, func(b *testing.B) {
			signature, err := regosig.NewRegoSignature(compile.TargetRego, false, bm.regoCodes...)
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

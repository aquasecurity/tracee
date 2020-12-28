package main

import (
	"testing"

	"github.com/aquasecurity/tracee/tracee-rules/signatures/signaturestest"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

func TestAntiDebuggingPtraceme(t *testing.T) {
	SigTests := []signaturestest.SigTest{
		{
			Events: []types.Event{
				types.TraceeEvent{
					EventName: "ptrace",
					ArgsNum:   1,
					Args: []types.TraceeEventArgument{
						{
							Name:  "request",
							Value: "PTRACE_TRACEME",
						},
					},
				},
			},
			Expect: true,
		},
		{
			Events: []types.Event{
				types.TraceeEvent{
					EventName: "ptrace",
					ArgsNum:   1,
					Args: []types.TraceeEventArgument{
						{
							Name:  "request",
							Value: "PTRACE_PEEKTEXT",
						},
					},
				},
			},
			Expect: false,
		},
	}
	for _, st := range SigTests {
		sig := antiDebuggingPtraceme{}
		st.Init(&sig)
		for _, e := range st.Events {
			err := sig.OnEvent(e)
			if err != nil {
				t.Error(err, st)
			}
		}
		if st.Expect != st.Status {
			t.Error("unexpected result", st)
		}
	}
}

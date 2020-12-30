package main

import (
	"testing"

	"github.com/aquasecurity/tracee/tracee-rules/types"
)

func TestAntiDebuggingPtraceme(t *testing.T) {
	sigTests := []sigTest{
		{
			events: []types.Event{
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
			expect: true,
		},
		{
			events: []types.Event{
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
			expect: false,
		},
	}
	for _, st := range sigTests {
		sig := antiDebuggingPtraceme{}
		st.init(&sig)
		for _, e := range st.events {
			err := sig.OnEvent(e)
			if err != nil {
				t.Error(err, st)
			}
		}
		if st.expect != st.status {
			t.Error("unexpected result", st)
		}
	}
}

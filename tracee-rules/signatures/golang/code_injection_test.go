package main

import (
	"testing"

	"github.com/aquasecurity/tracee/tracee-rules/types"
)

func TestCodeInjection(t *testing.T) {
	sigTests := []sigTest{
		{
			events: []types.Event{
				types.TraceeEvent{
					EventName: "ptrace",
					Args: []types.TraceeEventArgument{
						{
							Name:  "request",
							Value: "PTRACE_POKETEXT",
						},
					},
				},
			},
			expect: true,
		},
		{
			events: []types.Event{
				types.TraceeEvent{
					EventName: "open",
					Args: []types.TraceeEventArgument{
						{
							Name:  "pathname",
							Value: "/proc/self/mem",
						},
						{
							Name:  "flags",
							Value: "o_wronly",
						},
					},
				},
			},
			expect: true,
		},
		{
			events: []types.Event{
				types.TraceeEvent{
					EventName: "execve",
					Args: []types.TraceeEventArgument{
						{
							Name:  "envp",
							Value: []string{"FOO=BAR", "LD_PRELOAD=/something"},
						},
						{
							Name:  "argv",
							Value: []string{"ls"},
						},
					},
				},
			},
			expect: true,
		},
	}
	for _, st := range sigTests {
		sig := codeInjection{}
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

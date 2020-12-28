package main

import (
	"testing"

	"github.com/aquasecurity/tracee/tracee-rules/signatures/signaturestest"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

func TestCodeInjection(t *testing.T) {
	SigTests := []signaturestest.SigTest{
		{
			Events: []types.Event{
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
			Expect: true,
		},
		{
			Events: []types.Event{
				types.TraceeEvent{
					EventName: "ptrace",
					Args: []types.TraceeEventArgument{
						{
							Name:  "request",
							Value: "PTRACE_TRACEME",
						},
					},
				},
			},
			Expect: false,
		},
		{
			Events: []types.Event{
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
			Expect: true,
		},
		{
			Events: []types.Event{
				types.TraceeEvent{
					EventName: "open",
					Args: []types.TraceeEventArgument{
						{
							Name:  "pathname",
							Value: "/proc/foo",
						},
						{
							Name:  "flags",
							Value: "o_wronly",
						},
					},
				},
			},
			Expect: false,
		},
		{
			Events: []types.Event{
				types.TraceeEvent{
					EventName: "open",
					Args: []types.TraceeEventArgument{
						{
							Name:  "pathname",
							Value: "/proc/self/mem",
						},
						{
							Name:  "flags",
							Value: "o_rdonly",
						},
					},
				},
			},
			Expect: false,
		},
		{
			Events: []types.Event{
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
			Expect: true,
		},
		{
			Events: []types.Event{
				types.TraceeEvent{
					EventName: "execve",
					Args: []types.TraceeEventArgument{
						{
							Name:  "envp",
							Value: []string{"FOO=BAR"},
						},
						{
							Name:  "argv",
							Value: []string{"ls"},
						},
					},
				},
			},
			Expect: false,
		},
		{
			Events: []types.Event{
				types.TraceeEvent{
					EventName: "execve",
					Args: []types.TraceeEventArgument{
						{
							Name:  "argv",
							Value: []string{"ls"},
						},
					},
				},
			},
			Expect: false,
		},
	}
	for _, st := range SigTests {
		sig := codeInjection{}
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

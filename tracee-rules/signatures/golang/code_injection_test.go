package main

import (
	"testing"

	"github.com/aquasecurity/tracee/tracee-rules/signatures/signaturestest"
	"github.com/aquasecurity/tracee/tracee-rules/types"
	tracee "github.com/aquasecurity/tracee/tracee/external"
)

func TestCodeInjection(t *testing.T) {
	SigTests := []signaturestest.SigTest{
		{
			Events: []types.Event{
				tracee.Event{
					EventName: "ptrace",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "request",
							},
							Value: "PTRACE_POKETEXT",
						},
					},
				},
			},
			Expect: true,
		},
		{
			Events: []types.Event{
				tracee.Event{
					EventName: "ptrace",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "request",
							},
							Value: "PTRACE_TRACEME",
						},
					},
				},
			},
			Expect: false,
		},
		{
			Events: []types.Event{
				tracee.Event{
					EventName: "open",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "pathname",
							},
							Value: "/proc/self/mem",
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "flags",
							},
							Value: "o_wronly",
						},
					},
				},
			},
			Expect: true,
		},
		{
			Events: []types.Event{
				tracee.Event{
					EventName: "open",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "pathname",
							},
							Value: "/proc/foo",
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "flags",
							},
							Value: "o_wronly",
						},
					},
				},
			},
			Expect: false,
		},
		{
			Events: []types.Event{
				tracee.Event{
					EventName: "open",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "pathname",
							},
							Value: "/proc/self/mem",
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "flags",
							},
							Value: "o_rdonly",
						},
					},
				},
			},
			Expect: false,
		},
		{
			Events: []types.Event{
				tracee.Event{
					EventName: "execve",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "envp",
							},
							Value: []string{"FOO=BAR", "LD_PRELOAD=/something"},
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "argv",
							},
							Value: []string{"ls"},
						},
					},
				},
			},
			Expect: true,
		},
		{
			Events: []types.Event{
				tracee.Event{
					EventName: "execve",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "envp",
							},
							Value: []string{"FOO=BAR"},
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "argv",
							},
							Value: []string{"ls"},
						},
					},
				},
			},
			Expect: false,
		},
		{
			Events: []types.Event{
				tracee.Event{
					EventName: "execve",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "argv",
							},
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

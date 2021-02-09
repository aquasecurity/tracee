package main

import (
	tracee "github.com/aquasecurity/tracee/tracee/external"
	"testing"

	"github.com/aquasecurity/tracee/tracee-rules/signatures/signaturestest"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

func TestStdIoOverSocket(t *testing.T) {
	SigTests := []signaturestest.SigTest{
		{
			Events: []types.Event{
				tracee.Event{
					ProcessID: 45,
					EventName: "connect",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "sockfd",
							},
							Value: 5,
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "addr",
							},
							Value: "{'sa_family': 'AF_INET','sin_port': '53','sin_addr': '10.225.0.2'}",
						},
					},
				},
				tracee.Event{
					ProcessID: 45,
					EventName: "dup2",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "oldfd",
							},
							Value: 5,
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "newfd",
							},
							Value: 0,
						},
					},
				},
			},
			Expect: true,
		},
		{
			Events: []types.Event{
				tracee.Event{
					ProcessID: 45,
					EventName: "dup2",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "oldfd",
							},
							Value: 5,
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "newfd",
							},
							Value: 0,
						},
					},
				},
			},
			Expect: false,
		},
		{
			Events: []types.Event{
				tracee.Event{
					ProcessID: 45,
					EventName: "connect",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "sockfd",
							},
							Value: 5,
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "addr",
							},
							Value: "{'sa_family': 'AF_INET','sin_port': '53','sin_addr': '10.225.0.2'}",
						},
					},
				},
				tracee.Event{
					ProcessID: 45,
					EventName: "close",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "fd",
							},
							Value: 5,
						},
					},
				},
				tracee.Event{
					ProcessID: 45,
					EventName: "dup2",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "oldfd",
							},
							Value: 5,
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "newfd",
							},
							Value: 0,
						},
					},
				},
			},
			Expect: false,
		},
		{
			Events: []types.Event{
				tracee.Event{
					ProcessID: 45,
					EventName: "connect",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "sockfd",
							},
							Value: 5,
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "addr",
							},
							Value: "{'sa_family': 'AF_INET','sin_port': '53','sin_addr': '10.225.0.2'}",
						},
					},
				},
				tracee.Event{
					ProcessID: 22,
					EventName: "dup2",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "oldfd",
							},
							Value: 5,
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "newfd",
							},
							Value: 0,
						},
					},
				},
			},
			Expect: false,
		},
	}

	for _, st := range SigTests {
		sig := stdIoOverSocket{}
		st.Init(&sig)
		for _, e := range st.Events {
			err := sig.OnEvent(e)
			if err != nil {
				t.Error(err, st)
			}
		}
		if st.Expect != st.Status {
			t.Error("unExpected result", st)
		}
	}
}

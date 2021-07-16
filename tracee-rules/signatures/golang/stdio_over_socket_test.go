package main

import (
	tracee "github.com/aquasecurity/tracee/tracee-ebpf/external"
	"testing"

	"github.com/aquasecurity/tracee/tracee-rules/signatures/signaturestest"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

func TestStdioOverSocket(t *testing.T) {
	SigTests := []signaturestest.SigTest{
		{
			Events: []types.Event{
				tracee.Event{
					ProcessID: 45,
					EventName: "security_socket_connect",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "sockfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "remote_addr",
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
							Value: int32(5),
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "newfd",
							},
							Value: int32(0),
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
					EventName: "security_socket_connect",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "sockfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "remote_addr",
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
							Value: int32(5),
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "newfd",
							},
							Value: int32(0),
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
					EventName: "security_socket_connect",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "sockfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "remote_addr",
							},
							Value: "{'sa_family': 'AF_INET','sin_port': '53','sin_addr': '10.225.0.2'}",
						},
					},
				},
				tracee.Event{
					ProcessID:   45,
					EventName:   "dup",
					ReturnValue: 1,
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "oldfd",
							},
							Value: int32(5),
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
					EventName: "security_socket_connect",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "sockfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "remote_addr",
							},
							Value: "{'sa_family': 'AF_INET','sin_port': '53','sin_addr': '10.225.0.2'}",
						},
					},
				},
				tracee.Event{
					ProcessID: 45,
					EventName: "dup3",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "oldfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "newfd",
							},
							Value: int32(0),
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "flags",
							},
							Value: "SOMEFLAGS",
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
							Value: int32(5),
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "newfd",
							},
							Value: int32(0),
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
					EventName: "security_socket_connect",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "sockfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "remote_addr",
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
							Value: int32(5),
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
							Value: int32(5),
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "newfd",
							},
							Value: int32(0),
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
					EventName: "security_socket_connect",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "sockfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "remote_addr",
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
							Value: int32(5),
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "newfd",
							},
							Value: int32(0),
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
					EventName: "security_socket_connect",
					Args: []tracee.Argument{
						{
							ArgMeta: tracee.ArgMeta{
								Name: "sockfd",
							},
							Value: int32(5),
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "remote_addr",
							},
							Value: "{'sin6_scopeid': '0','sa_family': 'AF_INET6','sin6_port': '443','sin6_flowinfo': '0','sin6_addr': '2001:67c:1360:8001::2f'}",
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
							Value: int32(5),
						},
						{
							ArgMeta: tracee.ArgMeta{
								Name: "newfd",
							},
							Value: int32(0),
						},
					},
				},
			},
			Expect: true,
		},
	}

	for _, st := range SigTests {
		sig := stdioOverSocket{}
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

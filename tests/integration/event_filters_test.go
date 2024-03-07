package integration

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/goleak"

	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/events"
	k8s "github.com/aquasecurity/tracee/pkg/k8s/apis/tracee.aquasec.com/v1beta1"
	"github.com/aquasecurity/tracee/pkg/policy"
	"github.com/aquasecurity/tracee/pkg/policy/v1beta1"
	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/tests/testutils"
	"github.com/aquasecurity/tracee/types/trace"
)

// Test_EventFilters tests a variety of trace event filters
// with different combinations of policies
func Test_EventFilters(t *testing.T) {
	assureIsRoot(t)

	// Make sure we don't leak any goroutines since we run Tracee many times in this test.
	// If a test case fails, ignore the leak since it's probably caused by the aborted test.
	defer goleak.VerifyNone(t)

	// test table
	tt := []testCase{
		// events matched in single policies - detached workloads
		{
			name: "container: event: trace only events from new containers",
			policyFiles: []policyFileWithID{
				{
					id: 1,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "container-event",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"container=new",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event:   "-container_create",
									Filters: []string{},
								},
								{
									Event:   "-container_remove",
									Filters: []string{},
								},
							},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"docker run -d --rm hello-world",
					0,
					10*time.Second, // give some time for the container to start (possibly downloading the image)
					[]trace.Event{
						expectEvent(anyHost, "hello", anyProcessorID, 1, 0, events.SchedProcessExec, orPolNames("container-event"), orPolIDs(1)),
					},
					[]string{}, // no sets
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllInOrderSequentially,
		},
		{
			name: "mntns/pidns: trace events only from mount/pid namespace 0",
			policyFiles: []policyFileWithID{
				{
					id: 42,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "mntns/pidns",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"mntns=0", // no events expected
								"pidns=0", // no events expected
							},
							DefaultActions: []string{"log"},
							Rules:          []k8s.Rule{},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				// no event expected
				newCmdEvents("ls", 100*time.Millisecond, 1*time.Second, []trace.Event{}, []string{}),
				newCmdEvents("uname", 100*time.Millisecond, 1*time.Second, []trace.Event{}, []string{}),
				newCmdEvents("who", 100*time.Millisecond, 1*time.Second, []trace.Event{}, []string{}),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllInOrderSequentially,
		},
		{
			name: "mntns: trace events from all mount namespaces but current",
			policyFiles: []policyFileWithID{
				{
					id: 42,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "mntns",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"mntns!=" + getProcNS("mnt"), // no events expected
							},
							DefaultActions: []string{"log"},
							Rules:          []k8s.Rule{},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				// no event expected
				newCmdEvents("uname", 100*time.Millisecond, 1*time.Second, []trace.Event{}, []string{}),
				newCmdEvents("who", 100*time.Millisecond, 1*time.Second, []trace.Event{}, []string{}),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllInOrderSequentially,
		},
		{
			name: "pidns: trace events from all pid namespaces but current",
			policyFiles: []policyFileWithID{
				{
					id: 42,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "pidns",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"pidns!=" + getProcNS("pid"), // no events expected
							},
							DefaultActions: []string{"log"},
							Rules:          []k8s.Rule{},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				// no event expected
				newCmdEvents("uname", 100*time.Millisecond, 1*time.Second, []trace.Event{}, []string{}),
				newCmdEvents("who", 100*time.Millisecond, 1*time.Second, []trace.Event{}, []string{}),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllInOrderSequentially,
		},
		{
			name: "comm: mntns: pidns: event: trace events set in a single policy from current pid/mount namespaces",
			policyFiles: []policyFileWithID{
				{
					id: 1,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "comm_mntns_pidns_event",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=ping",
								"mntns=" + getProcNS("mnt"),
								"pidns=" + getProcNS("pid"),
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event:   "sched_process_exec",
									Filters: []string{},
								},
								{
									Event:   "sched_process_exit",
									Filters: []string{},
								},
							},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"ping -c1 0.0.0.0",
					0,
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "ping", testutils.CPUForTests, anyPID, 0, events.SchedProcessExec, orPolNames("comm_mntns_pidns_event"), orPolIDs(1)),
						expectEvent(anyHost, "ping", testutils.CPUForTests, anyPID, 0, events.SchedProcessExit, orPolNames("comm_mntns_pidns_event"), orPolIDs(1)),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllInOrderSequentially,
		},
		{
			name: "comm: event: trace events set in a single policy from ping command",
			policyFiles: []policyFileWithID{
				{
					id: 1,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "comm-event",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=ping",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event:   "sched_process_exec",
									Filters: []string{},
								},
								{
									Event:   "sched_process_exit",
									Filters: []string{},
								},
							},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"ping -c1 0.0.0.0",
					0,
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "ping", testutils.CPUForTests, anyPID, 0, events.SchedProcessExec, orPolNames("comm-event"), orPolIDs(1)),
						expectEvent(anyHost, "ping", testutils.CPUForTests, anyPID, 0, events.SchedProcessExit, orPolNames("comm-event"), orPolIDs(1)),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllInOrderSequentially,
		},
		{
			name: "comm: event: trace events set in a single policy from ping command",
			policyFiles: []policyFileWithID{
				{
					id: 5,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "comm-event",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=ping",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event:   "net_packet_icmp",
									Filters: []string{},
								},
							},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"ping -c1 0.0.0.0",
					0,
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "ping", testutils.CPUForTests, anyPID, 0, events.NetPacketICMP, orPolNames("comm-event"), orPolIDs(5)),
						expectEvent(anyHost, "ping", testutils.CPUForTests, anyPID, 0, events.NetPacketICMP, orPolNames("comm-event"), orPolIDs(5)),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllInOrderSequentially,
		},
		{
			name: "event: args: trace event set in a specific policy with args pathname finishing with 'ls'",
			policyFiles: []policyFileWithID{
				{
					id: 42,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "event-args",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"global",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event: "execve",
									Filters: []string{
										"args.pathname=*ls",
									},
								},
							},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"ls",
					0,
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "integration.tes", // note that comm name is from the go test binary that runs the command
							testutils.CPUForTests, anyPID, 0, events.Execve, orPolNames("event-args"), orPolIDs(42), expectArg("pathname", "*ls")),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllInOrderSequentially,
		},
		{
			name: "event: args: trace event set in a specific policy with args pathname starting with * wildcard",
			policyFiles: []policyFileWithID{
				{
					id: 42,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "event-args",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"global",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event: "execve",
									Filters: []string{
										"args.pathname=*/almost/improbable/path", // no event expected
									},
								},
							},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				// no event expected
				newCmdEvents("ls", 100*time.Millisecond, 1*time.Second, []trace.Event{}, []string{}),
				newCmdEvents("uname", 100*time.Millisecond, 1*time.Second, []trace.Event{}, []string{}),
				newCmdEvents("who", 100*time.Millisecond, 1*time.Second, []trace.Event{}, []string{}),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllInOrderSequentially,
		},
		{
			name: "comm: event: args: trace event set in a specific policy with args from ls command",
			policyFiles: []policyFileWithID{
				{
					id: 42,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "comm-event-args",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=ls",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event: "security_file_open",
									Filters: []string{
										"args.pathname=*integration",
									},
								},
							},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"ls",
					0,
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "ls", testutils.CPUForTests, anyPID, 0, events.SecurityFileOpen, orPolNames("comm-event-args"), orPolIDs(42), expectArg("pathname", "*integration")),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllInOrderSequentially,
		},
		{
			name: "comm: event: trace events set in two specific policies from ls and uname commands",
			policyFiles: []policyFileWithID{
				{
					id: 4,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "comm-event-4",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=ls",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event:   "sched_process_exit",
									Filters: []string{},
								},
							},
						},
					},
				},
				{
					id: 2,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "comm-event-2",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=uname",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event:   "sched_process_exit",
									Filters: []string{},
								},
							},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents("ls",
					0,
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "ls", testutils.CPUForTests, anyPID, 0, events.SchedProcessExit, orPolNames("comm-event-4"), orPolIDs(4)),
					},
					[]string{},
				),
				newCmdEvents("uname",
					0,
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "uname", testutils.CPUForTests, anyPID, 0, events.SchedProcessExit, orPolNames("comm-event-2"), orPolIDs(2)),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllInOrderSequentially,
		},
		{
			name: "exec: event: trace events in separate policies from who and uname executable",
			policyFiles: []policyFileWithID{
				{
					id: 1,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "exec-event-1",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"exec=/usr/bin/who",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event:   "sched_process_exec",
									Filters: []string{},
								},
							},
						},
					},
				},
				{
					id: 2,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "exec-event-2",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"exec=/usr/bin/uname",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event:   "sched_process_exec",
									Filters: []string{},
								},
							},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents("who",
					0,
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "who", testutils.CPUForTests, anyPID, 0, events.SchedProcessExec, orPolNames("exec-event-1"), orPolIDs(1)),
					},
					[]string{},
				),
				newCmdEvents("uname",
					0,
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "uname", testutils.CPUForTests, anyPID, 0, events.SchedProcessExec, orPolNames("exec-event-2"), orPolIDs(2)),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllInOrderSequentially,
		},
		// TODO: Add pid>0 pid<1000
		// TODO: Add u>0 u!=1000
		{
			name: "pid: event: args: trace event sched_switch with args from pid 0",
			policyFiles: []policyFileWithID{
				{
					id: 1,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "pid-0-event-args",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"pid=0",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event: "sched_switch",
									Filters: []string{
										"args.next_comm=systemd",
									},
								},
							},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"kill -SIGUSR1 1", // systemd: try to reconnect to the D-Bus bus
					500*time.Millisecond,
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, anyComm, anyProcessorID, 0, 0, events.SchedSwitch, orPolNames("pid-0-event-args"), orPolIDs(1), expectArg("next_comm", "systemd")),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     1 * time.Second,
			test:         ExpectAtLeastOneForEach,
		},
		{
			name: "pid: trace events from pid 1",
			policyFiles: []policyFileWithID{
				{
					id: 1,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "pid-1",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"pid=1",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event: "memfd_create,security_inode_unlink",
								},
							},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"kill -SIGHUP 1", // systemd: reloads the complete daemon configuration
					500*time.Millisecond,
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "systemd", anyProcessorID, 1, 0, events.MemfdCreate, orPolNames("pid-1"), orPolIDs(1)),
						expectEvent(anyHost, "systemd", anyProcessorID, 1, 0, events.SecurityInodeUnlink, orPolNames("pid-1"), orPolIDs(1)),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     1 * time.Second,
			test:         ExpectAnyOfEvts,
		},
		{
			name: "uid: comm: trace uid 0 from ls command",
			policyFiles: []policyFileWithID{
				{
					id: 1,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "uid-0-comm",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"uid=0",
								"comm=ls",
							},
							DefaultActions: []string{"log"},
							Rules:          []k8s.Rule{},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"ls",
					0,
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "ls", testutils.CPUForTests, anyPID, 0, anyEventID, orPolNames("uid-0-comm"), orPolIDs(1)),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllEvtsEqualToOne,
		},
		{
			name: "uid: comm: trace only uid>0 from ls command (should be empty)",
			policyFiles: []policyFileWithID{
				{
					id: 1,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "uid-0-comm",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"uid>0",
								"comm=ls",
							},
							DefaultActions: []string{"log"},
							Rules:          []k8s.Rule{},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"ls",
					100*time.Millisecond,
					1*time.Second,
					[]trace.Event{}, // no events expected
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllInOrderSequentially,
		},
		{
			name: "comm: trace filesystem events from ls command",
			policyFiles: []policyFileWithID{
				{
					id: 1,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "event-fs",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=ls",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event:   "fs", // fs set
									Filters: []string{},
								},
							},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"ls",
					0,
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "ls", testutils.CPUForTests, anyPID, 0, anyEventID, orPolNames("event-fs"), orPolIDs(1)),
					},
					[]string{"fs"},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllEvtsEqualToOne,
		},
		{
			name: "exec: event: trace only setns events from \"/usr/bin/dockerd\" executable",
			policyFiles: []policyFileWithID{
				{
					id: 1,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "exec-event",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"exec=/usr/bin/dockerd",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event:   "setns",
									Filters: []string{},
								},
							},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"docker run -d --rm hello-world",
					0,
					10*time.Second, // give some time for the container to start (possibly downloading the image)
					[]trace.Event{
						// using anyComm as some versions of dockerd may result in e.g. "dockerd" or "exe"
						expectEvent(anyHost, anyComm, anyProcessorID, anyPID, 0, events.Setns, orPolNames("exec-event"), orPolIDs(1)),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllInOrderSequentially,
		},
		{
			name: "pid: trace new (should be empty)",
			policyFiles: []policyFileWithID{
				{
					id: 1,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "pid-new",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"pid=new",
								"pid=1",
							},
							DefaultActions: []string{"log"},
							Rules:          []k8s.Rule{},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"kill -SIGUSR1 1", // systemd: try to reconnect to the D-Bus bus
					500*time.Millisecond,
					1*time.Second,
					[]trace.Event{}, // no events expected
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllInOrderSequentially,
		},
		{
			name: "comm: trace events set in a specific policy from ls command",
			policyFiles: []policyFileWithID{
				{
					id: 64,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "comm-64",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=ls",
							},
							DefaultActions: []string{"log"},
							Rules:          []k8s.Rule{},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"ls",
					0,
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "ls", testutils.CPUForTests, anyPID, 0, anyEventID, orPolNames("comm-64"), orPolIDs(64)),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllEvtsEqualToOne,
		},
		{
			name: "comm: trace events set in a specific policy from ls command",
			policyFiles: []policyFileWithID{
				{
					id: 64,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "comm-64",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=ls",
							},
							DefaultActions: []string{"log"},
							Rules:          []k8s.Rule{},
						},
					},
				},
				{
					// no events expected
					id: 42,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "comm-42",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=who",
							},
							DefaultActions: []string{"log"},
							Rules:          []k8s.Rule{},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"ls",
					0,
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "ls", testutils.CPUForTests, anyPID, 0, anyEventID, orPolNames("comm-64"), orPolIDs(64)),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllEvtsEqualToOne,
		},
		{
			name: "comm: trace events set in a specific policy from ls and who commands",
			policyFiles: []policyFileWithID{
				{
					id: 64,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "comm-64",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=ls",
							},
							DefaultActions: []string{"log"},
							Rules:          []k8s.Rule{},
						},
					},
				},
				{
					id: 42,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "comm-42",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=who",
							},
							DefaultActions: []string{"log"},
							Rules:          []k8s.Rule{},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"ls",
					0,
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "ls", testutils.CPUForTests, anyPID, 0, anyEventID, orPolNames("comm-64"), orPolIDs(64)),
					},
					[]string{},
				),
				newCmdEvents(
					"who",
					0,
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "who", testutils.CPUForTests, anyPID, 0, anyEventID, orPolNames("comm-42"), orPolIDs(42)),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllEvtsEqualToOne,
		},
		{
			name: "event: args: context: only security_file_open from \"execve\" syscall",
			policyFiles: []policyFileWithID{
				{
					id: 42,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "event-args-context",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"global",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event: "security_file_open",
									Filters: []string{
										"syscall=execve", // context
										"args.pathname=*ls",
									},
								},
							},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"bash -c ls",
					0,
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "bash", // note that comm name is from the runner
							testutils.CPUForTests, anyPID, 0, events.SecurityFileOpen, orPolNames("event-args-context"), orPolIDs(42), expectArg("pathname", "*ls")),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllEvtsEqualToOne,
		},
		{
			name: "comm: event: do a file write",
			policyFiles: []policyFileWithID{
				{
					id: 42,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "comm-event",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=tee",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event:   "magic_write",
									Filters: []string{},
								},
							},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"bash -c '/usr/bin/tee /tmp/magic_write_test < <(echo 42)'",
					0,
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "tee", testutils.CPUForTests, anyPID, 0, events.MagicWrite, orPolNames("comm-event"), orPolIDs(42)),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllInOrderSequentially,
		},

		// // TODO: add tests using signature events
		// // This is currently not possible since signature events are dynamically
		// // created and an event like anti_debugging is not known in advance.
		// {
		// 	name: "comm: event: args: sign: trace sys events + signature events in separate policies",
		// 	policyFiles: []policyFileWithID{
		// 		{
		// 			id: 3,
		// 			policyFile: v1beta1.PolicyFile{
		// 				Name:          "comm-event",
		// 				Scope:         []string{"comm=ping"},
		// 				DefaultActions: []string{"log"},
		// 				Rules: []k8s.Rule{
		// 					{
		// 						Event:  "net_packet_icmp",
		// 						Filters: []string{},
		// 					},
		// 				},
		// 			},
		// 		},
		// 		{
		// 			id: 5,
		// 			policyFile: v1beta1.PolicyFile{
		// 				Name:          "event-args",
		// 				Scope:         []string{},
		// 				DefaultActions: []string{"log"},
		// 				Rules: []k8s.Rule{
		// 					{
		// 						Event:  "ptrace",
		// 						Filters: []string{"args.pid=0"},
		// 					},
		// 				},
		// 			},
		// 		},
		// 		{
		// 			id: 9,
		// 			policyFile: v1beta1.PolicyFile{
		// 				Name:          "signature",
		// 				Scope:         []string{},
		// 				DefaultActions: []string{"log"},
		// 				Rules: []k8s.Rule{
		// 					{
		// 						Event:  "anti_debugging",
		// 						Filters: []string{},
		// 					},
		// 				},
		// 			},
		// 		},
		// 	},
		// 	cmdEvents: []cmdEvents{
		// 		newCmdEvents(
		// 			"ping -c1 0.0.0.0",
		// 			1*time.Second,
		// 			[]trace.Event{
		// 				expectEvent(anyHost, "ping", testutils.CPUForTests, anyPID, 0, events.NetPacketICMP, orPolNames("comm-event"), orPolIDs(3)),
		// 			},
		// 			[]string{},
		// 		),
		// 		newCmdEvents(
		// 			"strace ls",
		// 			1*time.Second,
		// 			[]trace.Event{
		// 				expectEvent(anyHost, "strace", testutils.CPUForTests, anyPID, 0, events.Ptrace, orPolNames("event-args"), orPolIDs(5)),
		// 				expectEvent(anyHost, "strace", testutils.CPUForTests, anyPID, 0, events.anti_debugging, orPolNames("sign"), orPolIDs(9)),
		// 			},
		// 			[]string{},
		// 		),
		// 	},
		// 	useSyscaller: false,
		// 	coolDown: 0,
		//  test: ExpectAtLeastOneOfEach,
		// },

		// events matched in multiple policies - intertwined workloads
		{
			name: "comm: event: trace events from ping command in multiple policies",
			policyFiles: []policyFileWithID{
				{
					id: 3,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "comm-event-3",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=ping",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event:   "net_packet_icmp",
									Filters: []string{},
								},
							},
						},
					},
				},
				{
					id: 5,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "comm-event-5",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=ping",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event:   "net_packet_icmp",
									Filters: []string{},
								},
							},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"ping -c1 0.0.0.0",
					100*time.Millisecond,
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "ping", testutils.CPUForTests, anyPID, 0, events.NetPacketICMP, orPolNames("comm-event-3", "comm-event-5"), orPolIDs(3, 5)),
						expectEvent(anyHost, "ping", testutils.CPUForTests, anyPID, 0, events.NetPacketICMP, orPolNames("comm-event-3", "comm-event-5"), orPolIDs(3, 5)),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllInOrderSequentially,
		},
		{
			name: "comm: event: trace events from ping command in multiple policies",
			policyFiles: []policyFileWithID{
				{
					id: 3,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "comm-event-3",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=ping",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event:   "net_packet_icmp",
									Filters: []string{},
								},
							},
						},
					},
				},
				{
					id: 5,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "comm-event-5",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=ping",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event:   "net_packet_icmp",
									Filters: []string{},
								},
								{
									Event:   "setuid",
									Filters: []string{},
								},
							},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"ping -c1 0.0.0.0",
					100*time.Millisecond,
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "ping", testutils.CPUForTests, anyPID, 0, events.Setuid, orPolNames("comm-event-5"), orPolIDs(5)),

						expectEvent(anyHost, "ping", testutils.CPUForTests, anyPID, 0, events.NetPacketICMP, orPolNames("comm-event-3", "comm-event-5"), orPolIDs(3, 5)),
						expectEvent(anyHost, "ping", testutils.CPUForTests, anyPID, 0, events.NetPacketICMP, orPolNames("comm-event-3", "comm-event-5"), orPolIDs(3, 5)),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllInOrderSequentially,
		},
		{
			name: "comm: event: trace events from ping command in multiple policies",
			policyFiles: []policyFileWithID{
				{
					id: 3,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "comm-event-3",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=ping",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event:   "net_packet_icmp",
									Filters: []string{},
								},
							},
						},
					},
				},
				{
					id: 5,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "comm-event-5",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=ping",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event:   "net_packet_icmp",
									Filters: []string{},
								},
							},
						},
					},
				},
				{
					id: 7,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "comm-event-7",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=ping",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event:   "sched_process_exec",
									Filters: []string{},
								},
							},
						},
					},
				},
				{
					id: 9,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "comm-event-9",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=ping",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event:   "sched_process_exec",
									Filters: []string{},
								},
								{
									Event:   "security_socket_connect",
									Filters: []string{},
								},
							},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"ping -c1 0.0.0.0",
					100*time.Millisecond,
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "ping", testutils.CPUForTests, anyPID, 0, events.SchedProcessExec, orPolNames("comm-event-7", "comm-event-9"), orPolIDs(7, 9)),

						expectEvent(anyHost, "ping", testutils.CPUForTests, anyPID, 0, events.SecuritySocketConnect, orPolNames("comm-event-9"), orPolIDs(9)),

						expectEvent(anyHost, "ping", testutils.CPUForTests, anyPID, 0, events.NetPacketICMP, orPolNames("comm-event-3", "comm-event-5"), orPolIDs(3, 5)),
						expectEvent(anyHost, "ping", testutils.CPUForTests, anyPID, 0, events.NetPacketICMP, orPolNames("comm-event-3", "comm-event-5"), orPolIDs(3, 5)),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllInOrderSequentially,
		},
		{
			name: "comm: trace only events from from ls and who commands in multiple policies",
			policyFiles: []policyFileWithID{
				{
					id: 64,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "comm-64",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=ls",
							},
							DefaultActions: []string{"log"},
							Rules:          []k8s.Rule{},
						},
					},
				},
				{
					id: 42,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "comm-42",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=who",
								"comm=ls",
							},
							DefaultActions: []string{"log"},
							Rules:          []k8s.Rule{},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"ls",
					0,
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "ls", testutils.CPUForTests, anyPID, 0, anyEventID, orPolNames("comm-64", "comm-42"), orPolIDs(64, 42)),
					},
					[]string{},
				),
				newCmdEvents(
					"who",
					0,
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "who", testutils.CPUForTests, anyPID, 0, anyEventID, orPolNames("comm-42"), orPolIDs(42)),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllEvtsEqualToOne,
		},
		{
			name: "comm: trace at least one event in multiple policies from ls and who commands",
			policyFiles: []policyFileWithID{
				{
					id: 64,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "comm-64",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=ls",
							},
							DefaultActions: []string{"log"},
							Rules:          []k8s.Rule{},
						},
					},
				},
				{
					id: 42,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "comm-42",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=who,ls",
							},
							DefaultActions: []string{"log"},
							Rules:          []k8s.Rule{},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"ls",
					0,
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "ls", testutils.CPUForTests, anyPID, 0, anyEventID, orPolNames("comm-64", "comm-42"), orPolIDs(64, 42)),
					},
					[]string{},
				),
				newCmdEvents(
					"who",
					0,
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "who", testutils.CPUForTests, anyPID, 0, anyEventID, orPolNames("comm-42"), orPolIDs(42)),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAtLeastOneForEach,
		},

		// This uses the syscaller tool which emits the desired events from a desired comm,
		// what is useful for testing events that are not easily triggered by a program.
		// In the following example, setting useSyscaller to true we use it to:
		// - impersonate a comm of "fakeprog1", based on runCmd arg passed in newCmdEvents
		// - emit read and write events, as defined in expected events
		{
			name: "comm: event: trace events read and write set in a single policy from fakeprog1 command",
			policyFiles: []policyFileWithID{
				{
					id: 1,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "comm-event",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=fakeprog1",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event:   "read",
									Filters: []string{},
								},
								{
									Event:   "write",
									Filters: []string{},
								},
							},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"fakeprog1",
					0,
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "fakeprog1", testutils.CPUForTests, anyPID, 0, events.Read, orPolNames("comm-event"), orPolIDs(1)),
						expectEvent(anyHost, "fakeprog1", testutils.CPUForTests, anyPID, 0, events.Write, orPolNames("comm-event"), orPolIDs(1)),
					},
					[]string{},
				),
			},
			useSyscaller: true,
			coolDown:     0,
			test:         ExpectAllInOrderSequentially,
		},
		{
			name: "event: trace execve event set in a specific policy from fakeprog1 command",
			policyFiles: []policyFileWithID{
				{
					id: 42,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "event-pol-42",
						},
						Spec: k8s.PolicySpec{
							Scope:          []string{"global"},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event:   "execve",
									Filters: []string{},
								},
							},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"fakeprog1",
					0,
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "fakeprog1", testutils.CPUForTests, anyPID, 0, events.Execve, orPolNames("event-pol-42"), orPolIDs(42)),
					},
					[]string{},
				),
			},
			useSyscaller: true,
			coolDown:     0,
			test:         ExpectAtLeastOneForEach,
		},
		{
			name: "comm: event: args: trace event set in a specific policy with args from fakeprog1 and fakeprog2 commands",
			policyFiles: []policyFileWithID{
				{
					id: 64,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "comm-event-args-64",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=fakeprog1",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event: "openat",
									Filters: []string{
										"args.dirfd=0",
										"args.flags=0",
										"args.mode=0",
									},
								},
							},
						},
					},
				},
				{
					id: 42,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "comm-event-args-42",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=fakeprog2",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event: "open",
									Filters: []string{
										"args.flags=0",
										"args.mode=0",
									},
								},
							},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"fakeprog1",
					0,
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "fakeprog1", testutils.CPUForTests, anyPID, 0, events.Openat, orPolNames("comm-event-args-64"), orPolIDs(64),
							expectArg("dirfd", int32(0)),
							expectArg("flags", int32(0)),
							expectArg("mode", uint32(0)),
						),
					},
					[]string{},
				),
				newCmdEvents(
					"fakeprog2",
					0,
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "fakeprog2", testutils.CPUForTests, anyPID, 0, events.Open, orPolNames("comm-event-args-42"), orPolIDs(42),
							expectArg("flags", int32(0)),
							expectArg("mode", uint32(0)),
						),
					},
					[]string{},
				),
			},
			useSyscaller: true,
			coolDown:     0,
			test:         ExpectAllInOrderSequentially,
		},
		{
			name: "comm: event: retval: trace event set in a specific policy with retval from fakeprog1 and fakeprog2 commands",
			policyFiles: []policyFileWithID{
				{
					id: 64,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "comm-event-retval-64",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=fakeprog1",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event: "openat",
									Filters: []string{
										"retval<0",
									},
								},
							},
						},
					},
				},
				{
					// no events expected
					id: 42,
					policyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "comm-event-retval-42",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=fakeprog2",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event: "open",
									Filters: []string{
										"retval>=0",
									},
								},
							},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"fakeprog1",
					0,
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "fakeprog1", testutils.CPUForTests, anyPID, 0, events.Openat, orPolNames("comm-event-retval-64"), orPolIDs(64),
							expectArg("dirfd", int32(0)),
							expectArg("flags", int32(0)),
							expectArg("mode", uint32(0)),
						),
					},
					[]string{},
				),
				newCmdEvents(
					"fakeprog2",
					100*time.Millisecond,
					1*time.Second,
					[]trace.Event{}, // no events expected
					[]string{},
				),
			},
			useSyscaller: true,
			coolDown:     0,
			test:         ExpectAllInOrderSequentially,
		},
	}

	// run tests cases
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			// wait for the previous test to cool down
			coolDown(t, tc.coolDown)

			// prepare tracee config
			cfg := config.Config{
				Capabilities: &config.CapabilitiesConfig{
					BypassCaps: true,
				},
				Capture: &config.CaptureConfig{
					FileWrite: config.FileCaptureConfig{},
					FileRead:  config.FileCaptureConfig{},
				},
			}

			// Prepare policies

			policies := newPolicies(cfg, tc.policyFiles)
			// TODO: remove this Store() when entire logic is moved to PolicyManager
			policy.Manager().Snapshots().Store(policies)

			ctx, cancel := context.WithCancel(context.Background())

			// start tracee
			trc, err := startTracee(ctx, t, cfg, nil, nil, policies)
			if err != nil {
				cancel()
				t.Fatal(err)
			}

			t.Logf("  --- started tracee ---")
			err = waitForTraceeStart(trc)
			if err != nil {
				cancel()
				t.Fatal(err)
			}

			stream := trc.SubscribeAll()
			defer trc.Unsubscribe(stream)

			// start a goroutine to read events from the channel into the buffer
			buf := newEventBuffer()
			go func(ctx context.Context, buf *eventBuffer) {
				for {
					select {
					case <-ctx.Done():
						return
					case evt := <-stream.ReceiveEvents():
						buf.addEvent(evt)
					}
				}
			}(ctx, buf)

			failed := false
			// run a test case and validate the results against the expected events
			err = tc.test(t, tc.cmdEvents, buf, tc.useSyscaller)
			if err != nil {
				t.Logf("Test %s failed: %v", t.Name(), err)
				failed = true
			}

			cancel()
			errStop := waitForTraceeStop(trc)
			if errStop != nil {
				t.Log(errStop)
				failed = true
			} else {
				t.Logf("  --- stopped tracee ---")
			}

			if failed {
				t.Fail()
			}
		})
	}
}

const (
	anyProcessorID = -1
	anyHost        = ""
	anyComm        = ""
	anyEventID     = -1
	anyPID         = -1
	anyUID         = -1
	anyPolicy      = 0
	anyPolicyName  = ""
)

type policyFileWithID struct {
	policyFile v1beta1.PolicyFile
	id         int
}

type testCase struct {
	name         string
	policyFiles  []policyFileWithID
	cmdEvents    []cmdEvents
	useSyscaller bool
	coolDown     time.Duration // cool down before running the test case
	test         func(t *testing.T, cmdEvents []cmdEvents, actual *eventBuffer, useSyscaller bool) error
}

type cmdEvents struct {
	runCmd  string
	waitFor time.Duration // time to wait before collecting events
	timeout time.Duration // timeout for the command to run
	evts    []trace.Event
	sets    []string
}

// newCmdEvents is a helper function to create a cmdEvents
func newCmdEvents(runCmd string, waitFor, timeout time.Duration, evts []trace.Event, sets []string) cmdEvents {
	return cmdEvents{
		runCmd:  runCmd,
		waitFor: waitFor,
		timeout: timeout,
		evts:    evts,
		sets:    sets,
	}
}

// newPolicies creates a new policies object with the given policies files with IDs.
func newPolicies(cfg config.Config, polsFilesID []policyFileWithID) policy.PoliciesBuilder {
	var polsFiles []k8s.PolicyInterface

	for _, polFile := range polsFilesID {
		polsFiles = append(polsFiles, polFile.policyFile)
	}

	policyScopeMap, policyEventMap, err := flags.PrepareFilterMapsFromPolicies(polsFiles)
	if err != nil {
		panic(err)
	}

	policies, err := flags.CreatePolicies(config.NewPoliciesConfig(cfg), policyScopeMap, policyEventMap, true)
	if err != nil {
		panic(err)
	}

	policiesWithIDSet := policy.NewPoliciesBuilder(config.NewPoliciesConfig(cfg))
	for pol := range policies.Map() {
		// fix the policy ID to match the one in the test
		correctedID := polsFilesID[pol.GetID()].id - 1
		policiesWithIDSet.Set(correctedID, pol)
	}

	return policiesWithIDSet
}

// orPolIDs is a helper function to create a bit mask of the given policies IDs
func orPolIDs(policies ...uint) uint64 {
	var res uint64

	for _, pol := range policies {
		utils.SetBit(&res, pol-1)
	}

	return res
}

// orPolNames is a helper function to create a slice of the given policies names
func orPolNames(policies ...string) []string {
	return policies
}

// expectArg is a helper function to create a trace.Argument with the name and value fields set
// If value has a star as wildcard, the value must be passed as it is due to test functions logic
func expectArg(name string, value interface{}) trace.Argument {
	return trace.Argument{
		ArgMeta: trace.ArgMeta{
			Name: name,
		},
		Value: value,
	}
}

// revive:disable:argument-limit
// expectEvent is a helper function to create a trace.Event
func expectEvent(
	host, comm string,
	processorID, pid, uid int,
	eventID events.ID,
	matchPolName []string,
	matchPols uint64,
	args ...trace.Argument,
) trace.Event {
	return trace.Event{
		ProcessorID:         processorID,
		ProcessID:           pid,
		UserID:              uid,
		ProcessName:         comm,
		HostName:            host,
		EventID:             int(eventID),
		MatchedPolicies:     matchPolName,
		MatchedPoliciesUser: matchPols,
		Args:                args,
	}
}

func coolDown(t *testing.T, duration time.Duration) {
	if duration > 0 {
		t.Logf("Cooling down for %v", duration)
		time.Sleep(duration)
	}
}

// proc represents a process, with its pid and the number of events it should generate
type proc struct {
	pid          int
	expectedEvts int
}

// runCmd runs a command and returns a process
func runCmd(t *testing.T, cmd cmdEvents, expectedEvts int, actual *eventBuffer, useSyscaller, failOnTimeout bool) (proc, error) {
	var (
		pid int
		err error
	)

	if useSyscaller {
		formatCmdEvents(&cmd)
	}

	t.Logf("  >>> running: %s", cmd.runCmd)
	pid, err = testutils.ExecPinnedCmdWithTimeout(cmd.runCmd, cmd.timeout)
	if err != nil {
		return proc{}, err
	}

	err = waitForTraceeOutputEvents(t, cmd.waitFor, actual, expectedEvts, failOnTimeout)
	if err != nil {
		return proc{}, err
	}

	return proc{
		pid:          pid,
		expectedEvts: expectedEvts,
	}, nil
}

// runCmds runs a list of commands and returns a list of processes
// It also returns the number of expected events from all processes
func runCmds(t *testing.T, cmdEvents []cmdEvents, actual *eventBuffer, useSyscaller, failOnTimeout bool) ([]proc, int, error) {
	var (
		procs          = make([]proc, 0)
		expectedEvts   int
		waitForAverage time.Duration
	)

	for _, cmd := range cmdEvents {
		var (
			pid int
			err error
		)

		if useSyscaller {
			formatCmdEvents(&cmd)
		}

		t.Logf("  >>> running: %s", cmd.runCmd)
		pid, err = testutils.ExecPinnedCmdWithTimeout(cmd.runCmd, cmd.timeout)
		if err != nil {
			return nil, 0, err
		}

		procs = append(procs, proc{pid, len(cmd.evts)})
		expectedEvts += len(cmd.evts)
		waitForAverage += cmd.waitFor
	}
	if waitForAverage > 0 {
		waitForAverage /= time.Duration(len(cmdEvents))
	}

	err := waitForTraceeOutputEvents(t, waitForAverage, actual, expectedEvts, failOnTimeout)
	if err != nil {
		return nil, 0, err
	}

	return procs, expectedEvts, nil
}

// formatCmdEvents formats given commands to be executed by syscaller helper tool
func formatCmdEvents(cmd *cmdEvents) {
	syscallerAbsPath := filepath.Join("..", "..", "dist", "syscaller")
	cmd.runCmd = fmt.Sprintf("%s %s", syscallerAbsPath, cmd.runCmd)

	for _, evt := range cmd.evts {
		cmd.runCmd = fmt.Sprintf("%s %d", cmd.runCmd, evt.EventID)
	}
}

// isInSets checks if a syscall is in a set of syscalls
func isInSets(syscallName string, sets []string) bool {
	for _, set := range sets {
		if syscallName == set {
			return true
		}
	}

	return false
}

// getAllSyscallsInSet returns all syscalls in given set
func getAllSyscallsInSet(set string) []string {
	var syscallsInSet []string

	for _, eventDefinition := range events.Core.GetDefinitions() {
		for _, c := range eventDefinition.GetSets() {
			if c == set {
				syscallsInSet = append(syscallsInSet, eventDefinition.GetName())
			}
		}
	}

	return syscallsInSet
}

// getAllSyscallsInSets returns all syscalls in given sets
func getAllSyscallsInSets(sets []string) []string {
	var syscallsInSet []string

	for _, set := range sets {
		syscallsInSet = append(syscallsInSet, getAllSyscallsInSet(set)...)
	}

	return syscallsInSet
}

// isCmdAShellRunner checks if the command is executed by a shell
func isCmdAShellRunner(cmd string) bool {
	if !strings.HasPrefix(cmd, "bash") && !strings.HasPrefix(cmd, "sh") {
		return false
	}
	if !strings.Contains(cmd, "-c") {
		return false
	}

	return true
}

// pidToCheck returns the pid of the process to check for events
func pidToCheck(cmd string, actEvt trace.Event) int {
	if isCmdAShellRunner(cmd) {
		return actEvt.ParentProcessID
	}

	return actEvt.ProcessID
}

// assert that the given string slices are equal, ignoring order
func assertUnorderedStringSlicesEqual(expNames []string, actNames []string) bool {
	if len(expNames) != len(actNames) {
		return false
	}
	sortedExpNames := make([]string, len(expNames))
	copy(sortedExpNames, expNames)
	sort.Strings(sortedExpNames)

	sortedActNames := make([]string, len(actNames))
	copy(sortedActNames, actNames)
	sort.Strings(sortedActNames)

	for i := range sortedExpNames {
		if sortedExpNames[i] != sortedActNames[i] {
			return false
		}
	}

	return true
}

// ExpectAtLeastOneForEach validates that at least one event from each command
// in 'cmdEvents' was captured in the actual events. It does not impose a minimum
// expected event count and checks that at least one event from each command
// (regardless of the number of expected events) is present in the actual events.
// It continues searching for all expected events for each command and raises a
// test failure only if none of the expected events for a command are found in
// the actual events.
//
// This function is suitable when you want to ensure that each command has at
// least one event in the actual events, regardless of the number of expected
// events for each command.
func ExpectAtLeastOneForEach(t *testing.T, cmdEvents []cmdEvents, actual *eventBuffer, useSyscaller bool) error {
	for _, cmd := range cmdEvents {
		syscallsInSets := []string{}
		checkSets := len(cmd.sets) > 0
		if checkSets {
			syscallsInSets = getAllSyscallsInSets(cmd.sets)
		}

		actual.clear()
		// first stage: run commands
		proc, err := runCmd(t, cmd, len(cmd.evts), actual, useSyscaller, true)
		if err != nil {
			return err
		}
		if len(cmd.evts) == 0 && proc.expectedEvts > 0 {
			return fmt.Errorf("expected no events for command %s, but got %d", cmd.runCmd, proc.expectedEvts)
		}

		actEvtsCopy := actual.getCopy()

		// second stage: validate events
		for _, expEvt := range cmd.evts {
			found := false
			checkHost := expEvt.HostName != anyHost
			checkComm := expEvt.ProcessName != anyComm
			checkProcessorID := expEvt.ProcessorID != anyProcessorID
			checkPID := expEvt.ProcessID != anyPID
			checkUID := expEvt.UserID != anyUID
			checkEventID := expEvt.EventID != anyEventID
			checkPolicy := expEvt.MatchedPoliciesUser != anyPolicy
			checkPolicyName := len(expEvt.MatchedPolicies) > 0 && expEvt.MatchedPolicies[0] != anyPolicyName

			if len(cmd.evts) > 0 && proc.expectedEvts == 0 {
				return fmt.Errorf("expected events for command %s, but got none", cmd.runCmd)
			}

			for _, actEvt := range actEvtsCopy {
				if checkSets && !isInSets(actEvt.EventName, syscallsInSets) {
					continue
				}

				if checkHost && actEvt.HostName != expEvt.HostName {
					continue
				}
				if checkComm && actEvt.ProcessName != expEvt.ProcessName {
					continue
				}
				if checkProcessorID && actEvt.ProcessorID != expEvt.ProcessorID {
					continue
				}
				if checkPID && pidToCheck(cmd.runCmd, actEvt) != expEvt.ProcessID {
					continue
				}
				if checkPID && actEvt.ProcessID != expEvt.ProcessID {
					continue
				}
				if checkUID && actEvt.UserID != expEvt.UserID {
					continue
				}
				if checkEventID && actEvt.EventID != expEvt.EventID {
					continue
				}
				if checkPolicy && actEvt.MatchedPoliciesUser != expEvt.MatchedPoliciesUser {
					continue
				}
				if checkPolicyName {
					polNameFound := false
					for _, policyName := range expEvt.MatchedPolicies {
						for _, actPolicyName := range actEvt.MatchedPolicies {
							if policyName == actPolicyName {
								polNameFound = true
								break
							}
						}
						if polNameFound {
							break
						}
					}

					if !polNameFound {
						continue
					}
				}

				// check args
				for _, expArg := range expEvt.Args {
					actArg, err := helpers.GetTraceeArgumentByName(actEvt, expArg.Name, helpers.GetArgOps{DefaultArgs: false})
					if err != nil {
						return err
					}
					switch v := expArg.Value.(type) {
					case string:
						actVal := actArg.Value.(string)
						if strings.Contains(v, "*") {
							v = strings.ReplaceAll(v, "*", "")
							if !strings.Contains(actVal, v) {
								continue
							}
						} else {
							if !assert.ObjectsAreEqual(v, actVal) {
								continue
							}
						}
					default:
						if !assert.ObjectsAreEqual(v, actArg.Value) {
							continue
						}
					}
				}

				// if we got here, it means we found a match and can stop searching
				found = true
				break
			}
			// evaluate found
			if !found {
				return fmt.Errorf("Event %+v:\nnot found in actual output:\n%+v", expEvt, actEvtsCopy)
			}
		}
	}

	return nil
}

// ExpectAnyOfEvts validates that at least one event from each command in
// 'cmdEvents' was captured in the actual events. It requires a minimum of two
// expected events for each command and stops searching as soon as it finds a
// matching event. If any command does not have at least one matching event in
// the actual events, it raises a test failure.
//
// This function is suitable when you expect any of a set of events to occur
// and want to confirm that at least one of them happened.
func ExpectAnyOfEvts(t *testing.T, cmdEvents []cmdEvents, actual *eventBuffer, useSyscaller bool) error {
	for _, cmd := range cmdEvents {
		if len(cmd.evts) <= 1 {
			return fmt.Errorf("ExpectAnyOfEvts test requires at least 2 expected events for command %s", cmd.runCmd)
		}

		syscallsInSets := []string{}
		checkSets := len(cmd.sets) > 0
		if checkSets {
			syscallsInSets = getAllSyscallsInSets(cmd.sets)
		}

		actual.clear()
		// first stage: run commands
		proc, err := runCmd(t, cmd, 1, actual, useSyscaller, true)
		if err != nil {
			return err
		}

		actEvtsCopy := actual.getCopy()

		// second stage: validate events
		found := false
		for _, expEvt := range cmd.evts {
			checkHost := expEvt.HostName != anyHost
			checkComm := expEvt.ProcessName != anyComm
			checkProcessorID := expEvt.ProcessorID != anyProcessorID
			checkPID := expEvt.ProcessID != anyPID
			checkUID := expEvt.UserID != anyUID
			checkEventID := expEvt.EventID != anyEventID
			checkPolicy := expEvt.MatchedPoliciesUser != anyPolicy
			checkPolicyName := len(expEvt.MatchedPolicies) > 0 && expEvt.MatchedPolicies[0] != anyPolicyName

			if len(cmd.evts) > 0 && proc.expectedEvts == 0 {
				return fmt.Errorf("expected events for command %s, but got none", cmd.runCmd)
			}

			for _, actEvt := range actEvtsCopy {
				if checkSets && !isInSets(actEvt.EventName, syscallsInSets) {
					continue
				}

				if checkHost && actEvt.HostName != expEvt.HostName {
					continue
				}
				if checkComm && actEvt.ProcessName != expEvt.ProcessName {
					continue
				}
				if checkProcessorID && actEvt.ProcessorID != expEvt.ProcessorID {
					continue
				}
				if checkPID && pidToCheck(cmd.runCmd, actEvt) != expEvt.ProcessID {
					continue
				}
				if checkPID && actEvt.ProcessID != expEvt.ProcessID {
					continue
				}
				if checkUID && actEvt.UserID != expEvt.UserID {
					continue
				}
				if checkEventID && actEvt.EventID != expEvt.EventID {
					continue
				}
				if checkPolicy && actEvt.MatchedPoliciesUser != expEvt.MatchedPoliciesUser {
					continue
				}
				if checkPolicyName {
					polNameFound := false
					for _, policyName := range expEvt.MatchedPolicies {
						for _, actPolicyName := range actEvt.MatchedPolicies {
							if policyName == actPolicyName {
								polNameFound = true
								break
							}
						}
						if polNameFound {
							break
						}
					}

					if !polNameFound {
						continue
					}
				}

				// check args
				for _, expArg := range expEvt.Args {
					actArg, err := helpers.GetTraceeArgumentByName(actEvt, expArg.Name, helpers.GetArgOps{DefaultArgs: false})
					if err != nil {
						return err
					}
					switch v := expArg.Value.(type) {
					case string:
						actVal := actArg.Value.(string)
						if strings.Contains(v, "*") {
							v = strings.ReplaceAll(v, "*", "")
							if !strings.Contains(actVal, v) {
								continue
							}
						} else {
							if !assert.ObjectsAreEqual(v, actVal) {
								continue
							}
						}
					default:
						if !assert.ObjectsAreEqual(v, actArg.Value) {
							continue
						}
					}
				}

				// if we got here, it means we found a match and can stop searching
				found = true
				break
			}

			if found {
				break
			}
		}

		// evaluate found
		if !found {
			return fmt.Errorf("none of the expected events\n%+v\nare in the actual output\n%+v", cmd.evts, actEvtsCopy)
		}
	}

	return nil
}

// ExpectAllEvtsEqualToOne validates that all events within a command match the
// single expected event for each command. It enforces that each command's events
// are exactly equal to the single expected event.
//
// This function is suitable for cases where each command should produce one
// specific event, and all commands should match their respective events.
func ExpectAllEvtsEqualToOne(t *testing.T, cmdEvents []cmdEvents, actual *eventBuffer, useSyscaller bool) error {
	for _, cmd := range cmdEvents {
		if len(cmd.evts) != 1 {
			return fmt.Errorf("ExpectAllEvtsEqualToOne test requires exactly one event per command, but got %d events for command %s", len(cmd.evts), cmd.runCmd)
		}

		actual.clear()
		// first stage: run commands
		proc, err := runCmd(t, cmd, len(cmd.evts), actual, useSyscaller, true)
		if err != nil {
			return err
		}

		actEvtsCopy := actual.getCopy()

		if proc.expectedEvts == 0 {
			return fmt.Errorf("expected one event for command %s, but got none", cmd.runCmd)
		}
		syscallsInSets := []string{}
		checkSets := len(cmd.sets) > 0
		if checkSets {
			syscallsInSets = getAllSyscallsInSets(cmd.sets)
		}

		// second stage: validate events
		for _, expEvt := range cmd.evts {
			checkHost := expEvt.HostName != anyHost
			checkComm := expEvt.ProcessName != anyComm
			checkProcessorID := expEvt.ProcessorID != anyProcessorID
			checkPID := expEvt.ProcessID != anyPID
			checkUID := expEvt.UserID != anyUID
			checkEventID := expEvt.EventID != anyEventID
			checkPolicy := expEvt.MatchedPoliciesUser != anyPolicy
			checkPolicyName := len(expEvt.MatchedPolicies) > 0 && expEvt.MatchedPolicies[0] != anyPolicyName

			for _, actEvt := range actEvtsCopy {
				if checkSets && !isInSets(actEvt.EventName, syscallsInSets) {
					return fmt.Errorf("Event %s not found in sets %v", actEvt.EventName, cmd.sets)
				}

				if checkHost && !assert.ObjectsAreEqual(expEvt.HostName, actEvt.HostName) {
					return fmt.Errorf("Event %+v:\nhost name mismatch: expected %s, got %s", expEvt, expEvt.HostName, actEvt.HostName)
				}
				if checkComm && !assert.ObjectsAreEqual(expEvt.ProcessName, actEvt.ProcessName) {
					return fmt.Errorf("Event %+v:\ncomm mismatch: expected %s, got %s", expEvt, expEvt.ProcessName, actEvt.ProcessName)
				}
				if checkProcessorID && !assert.ObjectsAreEqual(expEvt.ProcessorID, actEvt.ProcessorID) {
					return fmt.Errorf("Event %+v:\nprocessor id mismatch: expected %d, got %d", expEvt, expEvt.ProcessorID, actEvt.ProcessorID)
				}
				if checkPID {
					actPID := pidToCheck(cmd.runCmd, actEvt)
					if !assert.ObjectsAreEqual(expEvt.ProcessID, actPID) {
						return fmt.Errorf("Event %+v:\npid mismatch: expected %d, got %d", expEvt, expEvt.ProcessID, actPID)
					}
				}
				if checkUID && !assert.ObjectsAreEqual(expEvt.UserID, actEvt.UserID) {
					return fmt.Errorf("Event %+v:\nuser id mismatch: expected %d, got %d", expEvt, expEvt.UserID, actEvt.UserID)
				}
				if checkEventID && !assert.ObjectsAreEqual(expEvt.EventID, actEvt.EventID) {
					return fmt.Errorf("Event %+v:\nevent id mismatch: expected %d, got %d", expEvt, expEvt.EventID, actEvt.EventID)
				}
				if checkPolicy && !assert.ObjectsAreEqual(expEvt.MatchedPoliciesUser, actEvt.MatchedPoliciesUser) {
					return fmt.Errorf("Event %+v:\nmatched policies mismatch: expected %d, got %d", expEvt, expEvt.MatchedPoliciesUser, actEvt.MatchedPoliciesUser)
				}
				if checkPolicyName && !assertUnorderedStringSlicesEqual(expEvt.MatchedPolicies, actEvt.MatchedPolicies) {
					return fmt.Errorf("Event %+v:\nmatched policies mismatch: expected %v, got %v", expEvt, expEvt.MatchedPolicies, actEvt.MatchedPolicies)
				}

				// check args
				for _, expArg := range expEvt.Args {
					actArg, err := helpers.GetTraceeArgumentByName(actEvt, expArg.Name, helpers.GetArgOps{DefaultArgs: false})
					if err != nil {
						return err
					}
					switch v := expArg.Value.(type) {
					case string:
						actVal := actArg.Value.(string)
						if strings.Contains(v, "*") {
							v = strings.ReplaceAll(v, "*", "")
							if !strings.Contains(actVal, v) {
								return fmt.Errorf("Event %+v:\narg value mismatch: expected %s, got %s", expEvt, v, actVal)
							}
						} else {
							if !assert.ObjectsAreEqual(v, actVal) {
								return fmt.Errorf("Event %+v:\narg value mismatch: expected %s, got %s", expEvt, v, actVal)
							}
						}
					default:
						if !assert.ObjectsAreEqual(v, actArg.Value) {
							return fmt.Errorf("Event %+v:\narg value mismatch: expected %v, got %v", expEvt, v, actArg.Value)
						}
					}
				}
			}
		}
	}

	return nil
}

// ExpectAllInOrderSequentially validates that the actual events match the
// expected events for each command, with events appearing in the same order.
func ExpectAllInOrderSequentially(t *testing.T, cmdEvents []cmdEvents, actual *eventBuffer, useSyscaller bool) error {
	// first stage: run commands
	actual.clear()
	procs, _, err := runCmds(t, cmdEvents, actual, useSyscaller, true)
	if err != nil {
		return err
	}
	if len(procs) > len(cmdEvents) {
		return fmt.Errorf("expected %d commands, but got %d", len(cmdEvents), len(procs))
	}

	actEvtsCopy := actual.getCopy()

	// second stage: check events
	for cmdIdx, cmd := range cmdEvents {
		syscallsInSets := []string{}
		checkSets := len(cmd.sets) > 0
		if checkSets {
			syscallsInSets = getAllSyscallsInSets(cmd.sets)
		}

		// compare the expected events with the actual events in the same order
		for evtIdx, expEvt := range cmd.evts {
			actEvt := actEvtsCopy[cmdIdx*len(cmd.evts)+evtIdx]

			if checkSets && !isInSets(actEvt.EventName, syscallsInSets) {
				return fmt.Errorf("Event %s not found in sets %v", actEvt.EventName, cmd.sets)
			}
			checkHost := expEvt.HostName != anyHost
			checkComm := expEvt.ProcessName != anyComm
			checkProcessorID := expEvt.ProcessorID != anyProcessorID
			checkPID := expEvt.ProcessID != anyPID
			checkUID := expEvt.UserID != anyUID
			checkEventID := expEvt.EventID != anyEventID
			checkPolicy := expEvt.MatchedPoliciesUser != anyPolicy
			checkPolicyName := len(expEvt.MatchedPolicies) > 0 && expEvt.MatchedPolicies[0] != anyPolicyName

			if checkHost && !assert.ObjectsAreEqual(expEvt.HostName, actEvt.HostName) {
				return fmt.Errorf("Event %+v:\nhost name mismatch: expected %s, got %s", expEvt, expEvt.HostName, actEvt.HostName)
			}
			if checkComm && !assert.ObjectsAreEqual(expEvt.ProcessName, actEvt.ProcessName) {
				return fmt.Errorf("Event %+v:\ncomm mismatch: expected %s, got %s", expEvt, expEvt.ProcessName, actEvt.ProcessName)
			}
			if checkProcessorID && !assert.ObjectsAreEqual(expEvt.ProcessorID, actEvt.ProcessorID) {
				return fmt.Errorf("Event %+v:\nprocessor id mismatch: expected %d, got %d", expEvt, expEvt.ProcessorID, actEvt.ProcessorID)
			}
			if checkPID {
				actPID := pidToCheck(cmd.runCmd, actEvt)
				if !assert.ObjectsAreEqual(expEvt.ProcessID, actPID) {
					return fmt.Errorf("Event %+v:\npid mismatch: expected %d, got %d", expEvt, expEvt.ProcessID, actPID)
				}
			}
			if checkUID && !assert.ObjectsAreEqual(expEvt.UserID, actEvt.UserID) {
				return fmt.Errorf("Event %+v:\nuser id mismatch: expected %d, got %d", expEvt, expEvt.UserID, actEvt.UserID)
			}
			if checkEventID && !assert.ObjectsAreEqual(expEvt.EventID, actEvt.EventID) {
				return fmt.Errorf("Event %+v:\nevent id mismatch: expected %d, got %d", expEvt, expEvt.EventID, actEvt.EventID)
			}
			if checkPolicy && !assert.ObjectsAreEqual(expEvt.MatchedPoliciesUser, actEvt.MatchedPoliciesUser) {
				return fmt.Errorf("Event %+v:\nmatched policies mismatch: expected %d, got %d", expEvt, expEvt.MatchedPoliciesUser, actEvt.MatchedPoliciesUser)
			}
			if checkPolicyName && !assertUnorderedStringSlicesEqual(expEvt.MatchedPolicies, actEvt.MatchedPolicies) {
				return fmt.Errorf("Event %+v:\nmatched policies mismatch: expected %v, got %v", expEvt, expEvt.MatchedPolicies, actEvt.MatchedPolicies)
			}

			// check args
			for _, expArg := range expEvt.Args {
				actArg, err := helpers.GetTraceeArgumentByName(actEvt, expArg.Name, helpers.GetArgOps{DefaultArgs: false})
				if err != nil {
					return err
				}
				switch v := expArg.Value.(type) {
				case string:
					actVal := actArg.Value.(string)
					if strings.Contains(v, "*") {
						v = strings.ReplaceAll(v, "*", "")
						if !strings.Contains(actVal, v) {
							return fmt.Errorf("Event %+v:\narg value mismatch: expected %s, got %s", expEvt, v, actVal)
						}
					} else {
						if !assert.ObjectsAreEqual(v, actArg.Value) {
							return fmt.Errorf("Event %+v:\narg value mismatch: expected %s, got %s", expEvt, v, actVal)
						}
					}

				default:
					if !assert.ObjectsAreEqual(v, actArg.Value) {
						return fmt.Errorf("Event %+v:\narg value mismatch: expected %v, got %v", expEvt, v, actArg.Value)
					}
				}
			}
		}
	}

	return nil
}

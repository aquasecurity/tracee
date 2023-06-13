package integration

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/policy"
	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/aquasecurity/tracee/signatures/helpers"
	"github.com/aquasecurity/tracee/tests/integration/cpu"
	"github.com/aquasecurity/tracee/types/trace"
)

// Test_EventFilters tests a variety of trace event filters
// with different combinations of policies
func Test_EventFilters(t *testing.T) {
	if events.Definitions == nil {
		events.Definitions = events.NewEventGroup()
		err := events.Definitions.AddBatch(events.CoreDefinitions)
		assert.NoError(t, err)
	}

	// Make sure we don't leak any goroutines since we run Tracee many times in this test.
	// If a test case fails, ignore the leak since it's probably caused by the aborted test.
	defer goleak.VerifyNone(t)

	// test table
	tt := []testCase{
		// events matched in single policies - detached workloads
		{
			name: "container: event: trace only events from new containers",
			policies: []*policy.Policy{
				newPolicy(
					"container_event",
					1,
					[]string{
						"container=new",
						"event!=container_create,container_remove",
					},
				),
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"docker run -d --rm hello-world",
					10*time.Second, // give some time for the container to start (possibly downloading the image)
					[]trace.Event{
						expectEvent(anyHost, "hello", anyProcessorID, 1, 0, events.SchedProcessExec, orPolNames("container_event"), orPolIDs(1)),
					},
					[]string{}, // no sets
				),
			},
			useSyscaller: false,
			test:         ExpectAllInOrder,
		},
		{
			name: "comm: event: trace events set in a single policy from ping command",
			policies: []*policy.Policy{
				newPolicy(
					"comm_event",
					1,
					[]string{
						"comm=ping",
						"event=sched_process_exec,sched_process_exit",
					},
				),
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"ping -c1 0.0.0.0",
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "ping", cpu.CPUForTests, anyPID, 0, events.SchedProcessExec, orPolNames("comm_event"), orPolIDs(1)),
						expectEvent(anyHost, "ping", cpu.CPUForTests, anyPID, 0, events.SchedProcessExit, orPolNames("comm_event"), orPolIDs(1)),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			test:         ExpectAllInOrder,
		},
		{
			name: "comm: event: trace events set in a single policy from ping command",
			policies: []*policy.Policy{
				newPolicy(
					"comm_event",
					5,
					[]string{
						"comm=ping",
						"event=net_packet_icmp",
					},
				),
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"ping -c1 0.0.0.0",
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "ping", cpu.CPUForTests, anyPID, 0, events.NetPacketICMP, orPolNames("comm_event"), orPolIDs(5)),
						expectEvent(anyHost, "ping", cpu.CPUForTests, anyPID, 0, events.NetPacketICMP, orPolNames("comm_event"), orPolIDs(5)),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			test:         ExpectAllInOrder,
		},
		{
			name: "event: args: trace event set in a specific policy with args finishing with 'ls'",
			policies: []*policy.Policy{
				newPolicy(
					"event_args",
					42,
					[]string{
						"event=execve",
						"execve.args.pathname=*ls",
					},
				),
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"ls",
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "integration.tes", // note that comm name is from the go test binary that runs the command
							cpu.CPUForTests, anyPID, 0, events.Execve, orPolNames("event_args"), orPolIDs(42), expectArg("pathname", "*ls")),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			test:         ExpectAllInOrder,
		},
		{
			name: "event: args: trace event set in a specific policy with args starting with * wildcard",
			policies: []*policy.Policy{
				newPolicy(
					"comm_event_args",
					42,
					[]string{
						"event=execve",
						"execve.args.pathname=*/almost/improbable/path", // no event expected
					},
				),
			},
			cmdEvents: []cmdEvents{
				// no event expected
				newCmdEvents("ls", 1*time.Second, []trace.Event{}, []string{}),
				newCmdEvents("uname", 1*time.Second, []trace.Event{}, []string{}),
				newCmdEvents("who", 1*time.Second, []trace.Event{}, []string{}),
			},
			useSyscaller: false,
			test:         ExpectAllInOrder,
		},
		{
			name: "comm: event: args: trace event set in a specific policy with args from ls command",
			policies: []*policy.Policy{
				newPolicy(
					"comm_event_args",
					42,
					[]string{
						"comm=ls",
						"event=security_file_open",
						"security_file_open.args.pathname=*integration",
					},
				),
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"ls",
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "ls", cpu.CPUForTests, anyPID, 0, events.SecurityFileOpen, orPolNames("comm_event_args"), orPolIDs(42), expectArg("pathname", "*integration")),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			test:         ExpectAllInOrder,
		},
		{
			name: "comm: event: trace events set in two specific policies from ls and uname commands",
			policies: []*policy.Policy{
				newPolicy(
					"comm_event_4",
					4,
					[]string{
						"comm=ls",
						"event=sched_process_exit",
					},
				),
				newPolicy(
					"comm_event_2",
					2,
					[]string{
						"comm=uname",
						"event=sched_process_exit",
					},
				),
			},
			cmdEvents: []cmdEvents{
				newCmdEvents("ls",
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "ls", cpu.CPUForTests, anyPID, 0, events.SchedProcessExit, orPolNames("comm_event_4"), orPolIDs(4)),
					},
					[]string{},
				),
				newCmdEvents("uname",
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "uname", cpu.CPUForTests, anyPID, 0, events.SchedProcessExit, orPolNames("comm_event_2"), orPolIDs(2)),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			test:         ExpectAllInOrder,
		},
		{
			name: "bin: event: trace events in separate policies from who and uname binary",
			policies: []*policy.Policy{
				newPolicy(
					"bin_event_1",
					1,
					[]string{
						"bin=/usr/bin/who",
						"event=sched_process_exec",
					},
				),
				newPolicy(
					"bin_event_2",
					2,
					[]string{
						"bin=/usr/bin/uname",
						"event=sched_process_exec",
					}),
			},
			cmdEvents: []cmdEvents{
				newCmdEvents("who",
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "who", cpu.CPUForTests, anyPID, 0, events.SchedProcessExec, orPolNames("bin_event_1"), orPolIDs(1)),
					},
					[]string{},
				),
				newCmdEvents("uname",
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "uname", cpu.CPUForTests, anyPID, 0, events.SchedProcessExec, orPolNames("bin_event_2"), orPolIDs(2)),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			test:         ExpectAllInOrder,
		},
		// TODO: Add pid>0 pid<1000
		// TODO: Add u>0 u!=1000
		{
			name: "pid: event: args: trace event sched_switch with args from pid 0",
			policies: []*policy.Policy{
				newPolicy(
					"pid_0_event_args",
					1,
					[]string{
						"pid=0",
						"event=sched_switch",
						"sched_switch.args.next_comm=systemd,init",
					},
				),
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"kill -SIGHUP 1", // reloads the complete daemon configuration
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, anyComm, anyProcessorID, 0, 0, events.SchedSwitch, orPolNames("pid_0_event_args"), orPolIDs(1), expectArg("next_comm", "systemd")),
						expectEvent(anyHost, anyComm, anyProcessorID, 0, 0, events.SchedSwitch, orPolNames("pid_0_event_args"), orPolIDs(1), expectArg("next_comm", "init")),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			test:         ExpectAnyOfEach,
		},
		{
			name: "pid: trace events from pid 1",
			policies: []*policy.Policy{
				newPolicy(
					"pid_1",
					1,
					[]string{
						"pid=1",
					},
				),
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"kill -SIGHUP 1", // reloads the complete daemon configuration
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "init", anyProcessorID, 1, 0, anyEventID, orPolNames("pid_1"), orPolIDs(1)),
						expectEvent(anyHost, "systemd", anyProcessorID, 1, 0, anyEventID, orPolNames("pid_1"), orPolIDs(1)),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			test:         ExpectAnyOfEach,
		},
		{
			name: "uid: comm: trace uid 0 from ls command",
			policies: []*policy.Policy{
				newPolicy(
					"uid_0_comm",
					1,
					[]string{
						"uid=0",
						"comm=ls",
					},
				),
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"ls",
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "ls", cpu.CPUForTests, anyPID, 0, anyEventID, orPolNames("uid_0_comm"), orPolIDs(1)),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			test:         ExpectAllEqualTo,
		},
		{
			name: "uid: comm: trace only uid>0 from ls command (should be empty)",
			policies: []*policy.Policy{
				newPolicy( // no events expected
					"uid_0_comm",
					1,
					[]string{
						"uid>0",
						"comm=ls",
					},
				),
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"ls",
					1*time.Second,
					[]trace.Event{}, // no events expected
					[]string{},
				),
			},
			useSyscaller: false,
			test:         ExpectAllInOrder,
		},
		{
			name: "set: comm: trace filesystem events from ls command",
			policies: []*policy.Policy{
				newPolicy(
					"set_comm",
					1,
					[]string{
						"set=fs",
						"comm=ls",
					},
				),
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"ls",
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "ls", cpu.CPUForTests, anyPID, 0, anyEventID, orPolNames("set_comm"), orPolIDs(1)),
					},
					[]string{"fs"},
				),
			},
			useSyscaller: false,
			test:         ExpectAllEqualTo,
		},
		{
			name: "bin: event: trace only setns events from \"/usr/bin/dockerd\" binary",
			policies: []*policy.Policy{
				newPolicy(
					"bin_event",
					1,
					[]string{
						"bin=/usr/bin/dockerd",
						"event=setns",
					},
				),
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"docker run -d --rm hello-world",
					10*time.Second, // give some time for the container to start (possibly downloading the image)
					[]trace.Event{
						// using anyComm as some versions of dockerd may result in e.g. "dockerd" or "exe"
						expectEvent(anyHost, anyComm, anyProcessorID, anyPID, 0, events.Setns, orPolNames("bin_event"), orPolIDs(1)),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			test:         ExpectAllInOrder,
		},
		{
			name: "trace new pids (should be empty)",
			policies: []*policy.Policy{
				newPolicy( // no events expected
					"pid_new",
					1,
					[]string{
						"pid=new",
						"pid=1",
					},
				),
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"kill -SIGHUP 1", // reloads the complete daemon configuration
					1*time.Second,
					[]trace.Event{}, // no events expected
					[]string{},
				),
			},
			useSyscaller: false,
			test:         ExpectAllInOrder,
		},
		{
			name: "comm: trace events set in a specific policy from ls command",
			policies: []*policy.Policy{
				newPolicy(
					"comm_64",
					64,
					[]string{
						"comm=ls",
					},
				),
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"ls",
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "ls", cpu.CPUForTests, anyPID, 0, anyEventID, orPolNames("comm_64"), orPolIDs(64)),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			test:         ExpectAllEqualTo,
		},
		{
			name: "comm: trace events set in a specific policy from ls command",
			policies: []*policy.Policy{
				newPolicy(
					"comm_64",
					64,
					[]string{
						"comm=ls",
					},
				),
				newPolicy( // no events expected
					"comm_42",
					42,
					[]string{
						"comm=who",
					},
				),
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"ls",
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "ls", cpu.CPUForTests, anyPID, 0, anyEventID, orPolNames("comm_64"), orPolIDs(64)),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			test:         ExpectAllEqualTo,
		},
		{
			name: "comm: trace events set in a specific policy from ls and who commands",
			policies: []*policy.Policy{
				newPolicy(
					"comm_64",
					64,
					[]string{
						"comm=ls",
					},
				),
				newPolicy(
					"comm_42",
					42,
					[]string{
						"comm=who",
					},
				),
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"ls",
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "ls", cpu.CPUForTests, anyPID, 0, anyEventID, orPolNames("comm_64"), orPolIDs(64)),
					},
					[]string{},
				),
				newCmdEvents(
					"who",
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "who", cpu.CPUForTests, anyPID, 0, anyEventID, orPolNames("comm_42"), orPolIDs(42)),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			test:         ExpectAllEqualTo,
		},
		{
			name: "event: args: context: only security_file_open from \"execve\" syscall",
			policies: []*policy.Policy{
				newPolicy(
					"event_args_context",
					42,
					[]string{
						"event=security_file_open",
						"security_file_open.context.syscall=execve",
						"security_file_open.args.pathname=*ls",
					},
				),
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"bash -c ls",
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "bash", // note that comm name is from the runner
							cpu.CPUForTests, anyPID, 0, events.SecurityFileOpen, orPolNames("event_args_context"), orPolIDs(42), expectArg("pathname", "*ls")),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			test:         ExpectAllEqualTo,
		},
		{
			name: "comm: event: do a file write",
			policies: []*policy.Policy{
				newPolicy(
					"comm_event",
					42,
					[]string{
						"comm=tee",
						"event=magic_write",
					},
				),
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"bash -c '/usr/bin/tee /tmp/magic_write_test < <(echo 42)'",
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "tee", cpu.CPUForTests, anyPID, 0, events.MagicWrite, orPolNames("comm_event"), orPolIDs(42)),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			test:         ExpectAllInOrder,
		},

		// TODO: add tests using signature events
		// This is currently not possible since signature events are dynamically
		// created and an event like anti_debugging is not known in advance.
		// {
		// 	name: "comm: event: args: sign: trace sys events + signature events in separte policies",
		// 	policies: []*policy.Policy{
		// 		newPolicy(
		// 			"comm_event",
		// 			3,
		// 			[]string{
		// 				"comm=ping",
		// 				"event=net_packet_icmp",
		// 			},
		// 		),
		// 		newPolicy(
		// 			"event_args",
		// 			5,
		// 			[]string{
		// 				"event=ptrace",
		// 				"ptrace.args.pid=0",
		// 			},
		// 		),
		// 		newPolicy(
		// 			"sign",
		// 			9,
		// 			[]string{
		// 				"event=anti_debugging",
		// 			},
		// 		),
		// 	},
		// 	cmdEvents: []cmdEvents{
		// 		newCmdEvents(
		// 			"ping -c1 0.0.0.0",
		// 			1*time.Second,
		// 			[]trace.Event{
		// 				expectEvent(anyHost, "ping", cpu.CPUForTests, anyPID, 0, events.NetPacketICMP, "comm_event", orPolicies(3)),
		// 			},
		// 			[]string{},
		// 		),
		// 		newCmdEvents(
		// 			"strace ls",
		// 			1*time.Second,
		// 			[]trace.Event{
		// 				expectEvent(anyHost, "strace", cpu.CPUForTests, anyPID, 0, events.Ptrace, "event_args", orPolicies(5)),
		// 				expectEvent(anyHost, "strace", cpu.CPUForTests, anyPID, 0, events.anti_debugging, "sign", orPolicies(9)),
		// 			},
		// 			[]string{},
		// 		),
		// 	},
		// 	useSyscaller: false,
		// 	test:         ExpectAtLeastOneOfEach,
		// },

		// events matched in multiple policies - intertwined workloads
		{
			name: "comm: event: trace events from ping command in multiple policies",
			policies: []*policy.Policy{
				newPolicy(
					"comm_event_3",
					3,
					[]string{
						"comm=ping",
						"event=net_packet_icmp",
					},
				),
				newPolicy(
					"comm_event_5",
					5,
					[]string{
						"comm=ping",
						"event=net_packet_icmp",
					},
				),
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"ping -c1 0.0.0.0",
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "ping", cpu.CPUForTests, anyPID, 0, events.NetPacketICMP, orPolNames("comm_event_3", "comm_event_5"), orPolIDs(3, 5)),
						expectEvent(anyHost, "ping", cpu.CPUForTests, anyPID, 0, events.NetPacketICMP, orPolNames("comm_event_3", "comm_event_5"), orPolIDs(3, 5)),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			test:         ExpectAllInOrder,
		},
		{
			name: "comm: event: trace events from ping command in multiple policies",
			policies: []*policy.Policy{
				newPolicy(
					"comm_event_3",
					3,
					[]string{
						"comm=ping",
						"event=net_packet_icmp",
					},
				),
				newPolicy(
					"comm_event_5",
					5,
					[]string{
						"comm=ping",
						"event=net_packet_icmp,setuid",
					},
				),
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"ping -c1 0.0.0.0",
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "ping", cpu.CPUForTests, anyPID, 0, events.Setuid, orPolNames("comm_event_5"), orPolIDs(5)),

						expectEvent(anyHost, "ping", cpu.CPUForTests, anyPID, 0, events.NetPacketICMP, orPolNames("comm_event_3", "comm_event_5"), orPolIDs(3, 5)),
						expectEvent(anyHost, "ping", cpu.CPUForTests, anyPID, 0, events.NetPacketICMP, orPolNames("comm_event_3", "comm_event_5"), orPolIDs(3, 5)),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			test:         ExpectAllInOrder,
		},
		{
			name: "comm: event: trace events from ping command in multiple policies",
			policies: []*policy.Policy{
				newPolicy(
					"comm_event_3",
					3,
					[]string{
						"comm=ping",
						"event=net_packet_icmp",
					},
				),
				newPolicy(
					"comm_event_5",
					5,
					[]string{
						"comm=ping",
						"event=net_packet_icmp",
					},
				),
				newPolicy(
					"comm_event_7",
					7,
					[]string{
						"comm=ping",
						"event=sched_process_exec",
					},
				),
				newPolicy(
					"comm_event_9",
					9,
					[]string{
						"comm=ping",
						"event=sched_process_exec,security_socket_connect",
					},
				),
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"ping -c1 0.0.0.0",
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "ping", cpu.CPUForTests, anyPID, 0, events.SchedProcessExec, orPolNames("comm_event_7", "comm_event_9"), orPolIDs(7, 9)),

						expectEvent(anyHost, "ping", cpu.CPUForTests, anyPID, 0, events.SecuritySocketConnect, orPolNames("comm_event_9"), orPolIDs(9)),

						expectEvent(anyHost, "ping", cpu.CPUForTests, anyPID, 0, events.NetPacketICMP, orPolNames("comm_event_3", "comm_event_5"), orPolIDs(3, 5)),
						expectEvent(anyHost, "ping", cpu.CPUForTests, anyPID, 0, events.NetPacketICMP, orPolNames("comm_event_3", "comm_event_5"), orPolIDs(3, 5)),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			test:         ExpectAllInOrder,
		},
		{
			name: "comm: trace only events from from ls and who commands in multiple policies",
			policies: []*policy.Policy{
				newPolicy(
					"comm_64",
					64,
					[]string{
						"comm=ls",
					},
				),
				newPolicy(
					"comm_42",
					42,
					[]string{
						"comm=who,ls",
					},
				),
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"ls",
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "ls", cpu.CPUForTests, anyPID, 0, anyEventID, orPolNames("comm_64", "comm_42"), orPolIDs(64, 42)),
					},
					[]string{},
				),
				newCmdEvents(
					"who",
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "who", cpu.CPUForTests, anyPID, 0, anyEventID, orPolNames("comm_42"), orPolIDs(42)),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			test:         ExpectAllEqualTo,
		},
		{
			name: "comm: trace at least one event in multiple policies from ls and who commands",
			policies: []*policy.Policy{
				newPolicy(
					"comm_64",
					64,
					[]string{
						"comm=ls",
					},
				),
				newPolicy(
					"comm_42",
					42,
					[]string{
						"comm=who,ls",
					},
				),
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"ls",
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "ls", cpu.CPUForTests, anyPID, 0, anyEventID, orPolNames("comm_64", "comm_42"), orPolIDs(64, 42)),
					},
					[]string{},
				),
				newCmdEvents(
					"who",
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "who", cpu.CPUForTests, anyPID, 0, anyEventID, orPolNames("comm_42"), orPolIDs(42)),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			test:         ExpectAtLeastOneOfEach,
		},

		// This uses the syscaller tool which emits the desired events from a desired comm,
		// what is useful for testing events that are not easily triggered by a program.
		// In the following example, setting useSyscaller to true we use it to:
		// - impersonate a comm of "fakeprog1", based on runCmd arg passed in newCmdEvents
		// - emit read and write events, as defined in expected events
		{
			name: "comm: event: trace events read and write set in a single policy from fakeprog1 command",
			policies: []*policy.Policy{
				newPolicy(
					"comm_event",
					1,
					[]string{
						"comm=fakeprog1",
						"event=read,write",
					},
				),
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"fakeprog1",
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "fakeprog1", cpu.CPUForTests, anyPID, 0, events.Read, orPolNames("comm_event"), orPolIDs(1)),
						expectEvent(anyHost, "fakeprog1", cpu.CPUForTests, anyPID, 0, events.Write, orPolNames("comm_event"), orPolIDs(1)),
					},
					[]string{},
				),
			},
			useSyscaller: true,
			test:         ExpectAllInOrder,
		},
		{
			name: "event: trace execve event set in a specific policy from fakeprog1 command",
			policies: []*policy.Policy{
				newPolicy(
					"event_pol_42",
					42,
					[]string{
						"event=execve",
					},
				),
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"fakeprog1",
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "fakeprog1", cpu.CPUForTests, anyPID, 0, events.Execve, orPolNames("event_pol_42"), orPolIDs(42)),
					},
					[]string{},
				),
			},
			useSyscaller: true,
			test:         ExpectAtLeastOneOfEach,
		},
		{
			name: "comm: event: args: trace event set in a specific policy with args from fakeprog1 and fakeprog2 commands",
			policies: []*policy.Policy{
				newPolicy(
					"comm_event_args_64",
					64,
					[]string{
						"comm=fakeprog1",
						"event=openat",
						"openat.args.dirfd=0",
						"openat.args.flags=0",
						"openat.args.mode=0",
					},
				),
				newPolicy(
					"comm_event_args_42",
					42,
					[]string{
						"comm=fakeprog2",
						"event=open",
						"open.args.flags=0",
						"open.args.mode=0",
					},
				),
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"fakeprog1",
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "fakeprog1", cpu.CPUForTests, anyPID, 0, events.Openat, orPolNames("comm_event_args_64"), orPolIDs(64),
							expectArg("dirfd", int32(0)),
							expectArg("flags", int32(0)),
							expectArg("mode", uint32(0)),
						),
					},
					[]string{},
				),
				newCmdEvents(
					"fakeprog2",
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "fakeprog2", cpu.CPUForTests, anyPID, 0, events.Open, orPolNames("comm_event_args_42"), orPolIDs(42),
							expectArg("flags", int32(0)),
							expectArg("mode", uint32(0)),
						),
					},
					[]string{},
				),
			},
			useSyscaller: true,
			test:         ExpectAllInOrder,
		},
		{
			name: "comm: event: retval: trace event set in a specific policy with retval from fakeprog1 and fakeprog2 commands",
			policies: []*policy.Policy{
				newPolicy(
					"comm_event_retval_64",
					64,
					[]string{
						"comm=fakeprog1",
						"event=openat",
						"openat.retval<0",
					},
				),
				newPolicy( // no events expected
					"comm_event_retval_42",
					42,
					[]string{
						"comm=fakeprog2",
						"event=open",
						"open.retval>=0",
					},
				),
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"fakeprog1",
					1*time.Second,
					[]trace.Event{
						expectEvent(anyHost, "fakeprog1", cpu.CPUForTests, anyPID, 0, events.Openat, orPolNames("comm_event_retval_64"), orPolIDs(64),
							expectArg("dirfd", int32(0)),
							expectArg("flags", int32(0)),
							expectArg("mode", uint32(0)),
						),
					},
					[]string{},
				),
				newCmdEvents(
					"fakeprog2",
					1*time.Second,
					[]trace.Event{}, // no events expected
					[]string{},
				),
			},
			useSyscaller: true,
			test:         ExpectAllInOrder,
		},
	}

	// run tests cases
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			// prepare tracee config
			config := config.Config{
				Policies:   newPolicies(tc.policies...),
				ChanEvents: make(chan trace.Event, 1000),
				Capabilities: &config.CapabilitiesConfig{
					BypassCaps: true,
				},
			}

			ctx, cancel := context.WithCancel(context.Background())

			// start a goroutine to read events from the channel into the buffer
			buf := &eventBuffer{}
			go func(ctx context.Context) {
				for {
					select {
					case <-ctx.Done():
						return
					case evt := <-config.ChanEvents:
						buf.mu.Lock()
						buf.events = append(buf.events, evt)
						buf.mu.Unlock()
					}
				}
			}(ctx)

			// start tracee
			trc := startTracee(ctx, t, config, nil, nil)
			waitForTraceeStart(t, trc)

			// run a test case and validate the results against the expected events
			tc.test(t, tc.cmdEvents, buf, tc.useSyscaller)

			// if we got here, the test passed, so we can stop tracee
			cancel()
			waitForTraceeStop(t, trc)
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

type testCase struct {
	name         string
	policies     []*policy.Policy
	cmdEvents    []cmdEvents
	useSyscaller bool
	test         func(t *testing.T, cmdEvents []cmdEvents, actual *eventBuffer, useSyscaller bool)
}

type cmdEvents struct {
	runCmd  string
	timeout time.Duration
	evts    []trace.Event
	sets    []string
}

// newCmdEvents is a helper function to create a cmdEvents
func newCmdEvents(runCmd string, timeout time.Duration, evts []trace.Event, sets []string) cmdEvents {
	return cmdEvents{
		runCmd:  runCmd,
		timeout: timeout,
		evts:    evts,
		sets:    sets,
	}
}

// newPolicy creates a new policy with the given name, ID and filter flags
func newPolicy(name string, id int, filterFlags []string) *policy.Policy {
	filterMap, err := flags.PrepareFilterMapFromFlags(filterFlags)
	if err != nil {
		panic(err)
	}

	pols, err := flags.CreatePolicies(filterMap, true)
	if err != nil {
		panic(err)
	}

	// we need to set the pol name and ID manually because we are not using the pol engine
	// and we don't want to duplicate the logic of the pol engine here
	pol, err := pols.Lookup(0)
	if err != nil {
		panic(err)
	}

	pol.Name = name
	pol.ID = id - 1
	pols.Set(pol) // set policy ID using Set() method which checks ID range

	return pol
}

// newPolicies creates a new policies object with the given policies
func newPolicies(pols ...*policy.Policy) *policy.Policies {
	policies := policy.NewPolicies()

	for _, pol := range pols {
		policies.Set(pol)
	}

	return policies
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

// proc represents a process, with its pid and the number of events it should generate
type proc struct {
	pid          int
	expectedEvts int
}

// runCmd runs a command and returns a process
func runCmd(t *testing.T, cmd cmdEvents, actual *eventBuffer, useSyscaller, failOnTimeout bool) proc {
	var (
		pid int
		err error
	)

	if useSyscaller {
		formatCmdEvents(&cmd)
	}
	pid, err = execCmd(cmd.runCmd, cmd.timeout)
	require.NoError(t, err)

	waitForTraceeOutputEvents(t, actual, time.Now(), len(cmd.evts), failOnTimeout)

	return proc{
		pid:          pid,
		expectedEvts: len(cmd.evts),
	}
}

// runCmds runs a list of commands and returns a list of processes
// It also returns the number of expected events from all processes
func runCmds(t *testing.T, cmdEvents []cmdEvents, actual *eventBuffer, useSyscaller, failOnTimeout bool) ([]proc, int) {
	var (
		procs        = make([]proc, 0)
		expectedEvts int
	)

	for _, cmd := range cmdEvents {
		var (
			pid int
			err error
		)

		if useSyscaller {
			formatCmdEvents(&cmd)
		}
		pid, err = execCmd(cmd.runCmd, cmd.timeout)
		require.NoError(t, err)

		procs = append(procs, proc{pid, len(cmd.evts)})
		expectedEvts += len(cmd.evts)
	}

	waitForTraceeOutputEvents(t, actual, time.Now(), expectedEvts, failOnTimeout)

	return procs, expectedEvts
}

// formatCmdEvents formats given commands to be executed by syscaller helper tool
func formatCmdEvents(cmd *cmdEvents) {
	cmd.runCmd = fmt.Sprintf("./syscaller/cmd/syscaller %s", cmd.runCmd)
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

	for _, v := range events.Definitions.GetAllEvents() {
		for _, c := range v.GetSets() {
			if c == set {
				syscallsInSet = append(syscallsInSet, v.GetName())
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

// copyActualEvents returns a copy of the actual events
// This is to avoid holding the lock while comparing the events (in nested loops)
func copyActualEvents(actual *eventBuffer) []trace.Event {
	var evts []trace.Event

	actual.mu.Lock()
	evts = append(evts, actual.events...)
	actual.mu.Unlock()

	return evts
}

// assert that the given string slices are equal, ignoring order
func assertUnorderedStringSlicesEqual(t *testing.T, expNames []string, actNames []string) {
	assert.Equal(t, len(expNames), len(actNames))
	sortedExpNames := make([]string, len(expNames))
	copy(sortedExpNames, expNames)
	sort.Strings(sortedExpNames)

	sortedActNames := make([]string, len(actNames))
	copy(sortedActNames, actNames)
	sort.Strings(sortedActNames)

	for i := range sortedExpNames {
		assert.Equal(t, sortedExpNames[i], sortedActNames[i])
	}
}

// ExpectAtLeastOneOfEach validates that at least one event from each command was captured
func ExpectAtLeastOneOfEach(t *testing.T, cmdEvents []cmdEvents, actual *eventBuffer, useSyscaller bool) {
	for _, exp := range cmdEvents {
		syscallsInSets := []string{}
		checkSets := len(exp.sets) > 0
		if checkSets {
			syscallsInSets = getAllSyscallsInSets(exp.sets)
		}

		actual.clear()
		// first stage: run commands
		proc := runCmd(t, exp, actual, useSyscaller, true)
		if len(exp.evts) == 0 && proc.expectedEvts > 0 {
			t.Fatalf("expected no events for command %s, but got %d", exp.runCmd, proc.expectedEvts)
		}

		actEvtsCopy := copyActualEvents(actual)

		// second stage: validate events
		for _, expEvt := range exp.evts {
			found := false
			checkHost := expEvt.HostName != anyHost
			checkComm := expEvt.ProcessName != anyComm
			checkProcessorID := expEvt.ProcessorID != anyProcessorID
			checkPID := expEvt.ProcessID != anyPID
			checkUID := expEvt.UserID != anyUID
			checkEventID := expEvt.EventID != anyEventID
			checkPolicy := expEvt.MatchedPoliciesUser != anyPolicy
			checkPolicyName := len(expEvt.MatchedPolicies) > 0 && expEvt.MatchedPolicies[0] != anyPolicyName

			if len(exp.evts) > 0 && proc.expectedEvts == 0 {
				t.Fatalf("expected events for command %s, but got none", exp.runCmd)
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
				if checkPID && pidToCheck(exp.runCmd, actEvt) != expEvt.ProcessID {
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
					require.NoError(t, err)
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
			require.True(t, found, "Event %+v:\nnot found in actual output:\n%+v", expEvt, actual.events)
		}
	}
}

// ExpectAnyOfEach validates that at any event from each command was captured
func ExpectAnyOfEach(t *testing.T, cmdEvents []cmdEvents, actual *eventBuffer, useSyscaller bool) {
	for _, exp := range cmdEvents {
		syscallsInSets := []string{}
		checkSets := len(exp.sets) > 0
		if checkSets {
			syscallsInSets = getAllSyscallsInSets(exp.sets)
		}

		actual.clear()
		// first stage: run commands
		proc := runCmd(t, exp, actual, useSyscaller, true)
		if len(exp.evts) == 0 && proc.expectedEvts > 0 {
			t.Fatalf("expected no events for command %s, but got %d", exp.runCmd, proc.expectedEvts)
		}

		actEvtsCopy := copyActualEvents(actual)

		// second stage: validate events
		found := false
		for _, expEvt := range exp.evts {
			checkHost := expEvt.HostName != anyHost
			checkComm := expEvt.ProcessName != anyComm
			checkProcessorID := expEvt.ProcessorID != anyProcessorID
			checkPID := expEvt.ProcessID != anyPID
			checkUID := expEvt.UserID != anyUID
			checkEventID := expEvt.EventID != anyEventID
			checkPolicy := expEvt.MatchedPoliciesUser != anyPolicy
			checkPolicyName := len(expEvt.MatchedPolicies) > 0 && expEvt.MatchedPolicies[0] != anyPolicyName

			if len(exp.evts) > 0 && proc.expectedEvts == 0 {
				t.Fatalf("expected events for command %s, but got none", exp.runCmd)
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
				if checkPID && pidToCheck(exp.runCmd, actEvt) != expEvt.ProcessID {
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
					require.NoError(t, err)
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
		require.True(t, found, "None of the expected events\n%+v\nare in the actual output\n%+v\n", exp.evts, actEvtsCopy)
	}
}

// ExpectAllEqualTo expects all events to be equal to the expected events
func ExpectAllEqualTo(t *testing.T, cmdEvents []cmdEvents, actual *eventBuffer, useSyscaller bool) {
	for _, exp := range cmdEvents {
		if len(exp.evts) != 1 {
			t.Fatalf("ExpectAllEqualTo test requires exactly one event per command")
		}

		actual.clear()
		// first stage: run commands
		proc := runCmd(t, exp, actual, useSyscaller, true)
		actEvtsCopy := copyActualEvents(actual)

		if proc.expectedEvts == 0 {
			t.Fatalf("expected one event for command %s, but got none", exp.runCmd)
		}
		syscallsInSets := []string{}
		checkSets := len(exp.sets) > 0
		if checkSets {
			syscallsInSets = getAllSyscallsInSets(exp.sets)
		}

		// second stage: validate events
		for _, expEvt := range exp.evts {
			checkHost := expEvt.HostName != anyHost
			checkComm := expEvt.ProcessName != anyComm
			checkProcessorID := expEvt.ProcessorID != anyProcessorID
			checkPID := expEvt.ProcessID != anyPID
			checkUID := expEvt.UserID != anyUID
			checkEventID := expEvt.EventID != anyEventID
			checkPolicy := expEvt.MatchedPoliciesUser != anyPolicy
			checkPolicyName := len(expEvt.MatchedPolicies) > 0 && expEvt.MatchedPolicies[0] != anyPolicyName

			for _, actEvt := range actEvtsCopy {
				if checkSets {
					assert.Contains(t, syscallsInSets, actEvt.EventName, "event name in set")
				}

				if checkHost {
					assert.Equal(t, expEvt.HostName, actEvt.HostName, "host name")
				}
				if checkComm {
					assert.Equal(t, expEvt.ProcessName, actEvt.ProcessName, "comm")
				}
				if checkProcessorID {
					assert.Equal(t, expEvt.ProcessorID, actEvt.ProcessorID, "processor id")
				}
				if checkPID {
					assert.Equal(t, expEvt.ProcessID, pidToCheck(exp.runCmd, actEvt), "pid")
				}
				if checkUID {
					assert.Equal(t, expEvt.UserID, actEvt.UserID, "user id")
				}
				if checkEventID {
					assert.Equal(t, expEvt.EventID, actEvt.EventID, "event id")
				}
				if checkPolicy {
					assert.Equal(t, expEvt.MatchedPoliciesUser, actEvt.MatchedPoliciesUser, "matched policies")
				}
				if checkPolicyName {
					assertUnorderedStringSlicesEqual(t, expEvt.MatchedPolicies, actEvt.MatchedPolicies)
				}

				// check args
				for _, expArg := range expEvt.Args {
					actArg, err := helpers.GetTraceeArgumentByName(actEvt, expArg.Name, helpers.GetArgOps{DefaultArgs: false})
					require.NoError(t, err)
					switch v := expArg.Value.(type) {
					case string:
						actVal := actArg.Value.(string)
						if strings.Contains(v, "*") {
							v = strings.ReplaceAll(v, "*", "")
							assert.Contains(t, actVal, v, "arg value")
						} else {
							assert.Equal(t, v, actVal, "arg value")
						}
					default:
						assert.Equal(t, v, actArg.Value, "arg value")
					}
				}
			}
		}
	}
}

// ExpectAllInOrder expects all events to be equal to the expected events in the same order
func ExpectAllInOrder(t *testing.T, cmdEvents []cmdEvents, actual *eventBuffer, useSyscaller bool) {
	// first stage: run commands
	actual.clear()
	procs, _ := runCmds(t, cmdEvents, actual, useSyscaller, true)
	if len(procs) > len(cmdEvents) {
		t.Fatalf("expected %d commands, but got %d", len(cmdEvents), len(procs))
	}
	actEvtsCopy := copyActualEvents(actual)

	// second stage: check events
	for cmdIdx, exp := range cmdEvents {
		syscallsInSets := []string{}
		checkSets := len(exp.sets) > 0
		if checkSets {
			syscallsInSets = getAllSyscallsInSets(exp.sets)
		}

		// compare the expected events with the actual events in the same order
		for evtIdx, expEvt := range exp.evts {
			actEvt := actEvtsCopy[cmdIdx*len(exp.evts)+evtIdx]

			if checkSets {
				assert.Contains(t, syscallsInSets, actEvt.EventName, "event name in set")
			}
			checkHost := expEvt.HostName != anyHost
			checkComm := expEvt.ProcessName != anyComm
			checkProcessorID := expEvt.ProcessorID != anyProcessorID
			checkPID := expEvt.ProcessID != anyPID
			checkUID := expEvt.UserID != anyUID
			checkEventID := expEvt.EventID != anyEventID
			checkPolicy := expEvt.MatchedPoliciesUser != anyPolicy
			checkPolicyName := len(expEvt.MatchedPolicies) > 0 && expEvt.MatchedPolicies[0] != anyPolicyName

			if checkHost {
				assert.Equal(t, expEvt.HostName, actEvt.HostName, "host name")
			}
			if checkComm {
				assert.Equal(t, expEvt.ProcessName, actEvt.ProcessName, "comm")
			}
			if checkProcessorID {
				assert.Equal(t, expEvt.ProcessorID, actEvt.ProcessorID, "processor id")
			}
			if checkPID {
				assert.Equal(t, expEvt.ProcessID, pidToCheck(exp.runCmd, actEvt), "pid")
			}
			if checkUID {
				assert.Equal(t, expEvt.UserID, actEvt.UserID, "user id")
			}
			if checkEventID {
				assert.Equal(t, expEvt.EventID, actEvt.EventID, "event id")
			}
			if checkPolicy {
				assert.Equal(t, expEvt.MatchedPoliciesUser, actEvt.MatchedPoliciesUser, "matched policies")
			}
			if checkPolicyName {
				assertUnorderedStringSlicesEqual(t, expEvt.MatchedPolicies, actEvt.MatchedPolicies)
			}

			// check args
			for _, expArg := range expEvt.Args {
				actArg, err := helpers.GetTraceeArgumentByName(actEvt, expArg.Name, helpers.GetArgOps{DefaultArgs: false})
				require.NoError(t, err)
				switch v := expArg.Value.(type) {
				case string:
					if strings.Contains(v, "*") {
						v = strings.ReplaceAll(v, "*", "")
						assert.Contains(t, actArg.Value, v, "arg value")
					} else {
						assert.Equal(t, v, actArg.Value, "arg value")
					}

				default:
					assert.Equal(t, v, actArg.Value, "arg value")
				}
			}
		}
	}
}

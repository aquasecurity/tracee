package integration

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"google.golang.org/protobuf/types/known/wrapperspb"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/events"
	k8s "github.com/aquasecurity/tracee/pkg/k8s/apis/tracee.aquasec.com/v1beta1"
	"github.com/aquasecurity/tracee/pkg/policy/v1beta1"
	"github.com/aquasecurity/tracee/tests/testutils"
	"github.com/aquasecurity/tracee/types/trace"
)

// Test_EventFilters tests a variety of trace event filters
// with different combinations of policies
func Test_EventFilters(t *testing.T) {
	testutils.AssureIsRoot(t)

	// Make sure we don't leak any goroutines since we run Tracee many times in this test.
	// If a test case fails, ignore the leak since it's probably caused by the aborted test.
	defer goleak.VerifyNone(t)

	// Pre-pull Docker images to avoid transient failures during tests.
	// This prevents race conditions and network issues when Docker tries to pull
	// images while tests are running.
	for _, image := range []string{busyboxImage, ubuntuJammyPinnedImage} {
		t.Logf("Pre-pulling Docker image: %s", image)
		pullCmd := exec.Command("docker", "image", "pull", image)
		if err := pullCmd.Run(); err != nil {
			t.Logf("Warning: failed to pre-pull image %s: %v (tests may still work if cached)", image, err)
		}
	}

	// Setup test logger
	teardown := testutils.EnableTestLogger(t, logger.InfoLevel)
	defer teardown()

	// test table
	tt := []testCase{
		// events matched in single policies - detached workloads
		{
			name: "container: event: trace only events from new containers",
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 1,
					PolicyFile: v1beta1.PolicyFile{
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
					"docker run -d --rm "+busyboxImage,
					0,
					10*time.Second, // give some time for the container to start (possibly downloading the image)
					[]*pb.Event{
						expectPbEvent(anyHost, "sh", anyProcessorID, 1, 0, events.SchedProcessExec, orPolNames("container-event")),
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
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 42,
					PolicyFile: v1beta1.PolicyFile{
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
				newCmdEvents("ls", 100*time.Millisecond, 1*time.Second, []*pb.Event{}, []string{}),
				newCmdEvents("uname", 100*time.Millisecond, 1*time.Second, []*pb.Event{}, []string{}),
				newCmdEvents("who", 100*time.Millisecond, 1*time.Second, []*pb.Event{}, []string{}),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllInOrderSequentially,
		},
		{
			name: "mntns: trace events from all mount namespaces but current",
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 42,
					PolicyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "mntns",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"mntns!=" + testutils.GetProcNS("mnt"), // no events expected
							},
							DefaultActions: []string{"log"},
							Rules:          []k8s.Rule{},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				// no event expected
				newCmdEvents("uname", 100*time.Millisecond, 1*time.Second, []*pb.Event{}, []string{}),
				newCmdEvents("who", 100*time.Millisecond, 1*time.Second, []*pb.Event{}, []string{}),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllInOrderSequentially,
		},
		{
			name: "pidns: trace events from all pid namespaces but current",
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 42,
					PolicyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "pidns",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"pidns!=" + testutils.GetProcNS("pid"), // no events expected
							},
							DefaultActions: []string{"log"},
							Rules:          []k8s.Rule{},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				// no event expected
				newCmdEvents("uname", 100*time.Millisecond, 1*time.Second, []*pb.Event{}, []string{}),
				newCmdEvents("who", 100*time.Millisecond, 1*time.Second, []*pb.Event{}, []string{}),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllInOrderSequentially,
		},
		{
			name: "comm: mntns: pidns: event: trace events set in a single policy from current pid/mount namespaces",
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 1,
					PolicyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "comm_mntns_pidns_event",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=ping",
								"mntns=" + testutils.GetProcNS("mnt"),
								"pidns=" + testutils.GetProcNS("pid"),
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
					[]*pb.Event{
						expectPbEvent(anyHost, "ping", testutils.CPUForTests, anyPID, 0, events.SchedProcessExec, orPolNames("comm_mntns_pidns_event")),
						expectPbEvent(anyHost, "ping", testutils.CPUForTests, anyPID, 0, events.SchedProcessExit, orPolNames("comm_mntns_pidns_event")),
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
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 1,
					PolicyFile: v1beta1.PolicyFile{
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
					[]*pb.Event{
						expectPbEvent(anyHost, "ping", testutils.CPUForTests, anyPID, 0, events.SchedProcessExec, orPolNames("comm-event")),
						expectPbEvent(anyHost, "ping", testutils.CPUForTests, anyPID, 0, events.SchedProcessExit, orPolNames("comm-event")),
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
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 5,
					PolicyFile: v1beta1.PolicyFile{
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
					[]*pb.Event{
						expectPbEvent(anyHost, "ping", testutils.CPUForTests, anyPID, 0, events.NetPacketICMP, orPolNames("comm-event")),
						expectPbEvent(anyHost, "ping", testutils.CPUForTests, anyPID, 0, events.NetPacketICMP, orPolNames("comm-event")),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllInOrderSequentially,
		},
		{
			name: "event: data: trace event set in a specific policy with data pathname finishing with 'ls'",
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 42,
					PolicyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "event-data",
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
										"data.pathname=*/ls",
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
					[]*pb.Event{
						expectPbEvent(anyHost, "integration.tes", // note that comm name is from the go test binary that runs the command
							testutils.CPUForTests, anyPID, 0, events.Execve, orPolNames("event-data"), expectPbArg("pathname", "*/ls")),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllInOrderSequentially,
		},
		{
			name: "event: data: trace event set in a specific policy with data pathname starting with * wildcard",
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 42,
					PolicyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "event-data",
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
										"data.pathname=*/almost/improbable/path", // no event expected
									},
								},
							},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				// no event expected
				newCmdEvents("ls", 100*time.Millisecond, 1*time.Second, []*pb.Event{}, []string{}),
				newCmdEvents("uname", 100*time.Millisecond, 1*time.Second, []*pb.Event{}, []string{}),
				newCmdEvents("who", 100*time.Millisecond, 1*time.Second, []*pb.Event{}, []string{}),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllInOrderSequentially,
		},
		{
			name: "comm: event: data: trace event set in a specific policy with data from ls command",
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 42,
					PolicyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "comm-event-data",
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
										"data.pathname=*integration",
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
					[]*pb.Event{
						expectPbEvent(anyHost, "ls", testutils.CPUForTests, anyPID, 0, events.SecurityFileOpen, orPolNames("comm-event-data"), expectPbArg("pathname", "*integration")),
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
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 4,
					PolicyFile: v1beta1.PolicyFile{
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
					Id: 2,
					PolicyFile: v1beta1.PolicyFile{
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
					[]*pb.Event{
						expectPbEvent(anyHost, "ls", testutils.CPUForTests, anyPID, 0, events.SchedProcessExit, orPolNames("comm-event-4")),
					},
					[]string{},
				),
				newCmdEvents("uname",
					0,
					1*time.Second,
					[]*pb.Event{
						expectPbEvent(anyHost, "uname", testutils.CPUForTests, anyPID, 0, events.SchedProcessExit, orPolNames("comm-event-2")),
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
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 1,
					PolicyFile: v1beta1.PolicyFile{
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
					Id: 2,
					PolicyFile: v1beta1.PolicyFile{
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
					[]*pb.Event{
						expectPbEvent(anyHost, "who", testutils.CPUForTests, anyPID, 0, events.SchedProcessExec, orPolNames("exec-event-1")),
					},
					[]string{},
				),
				newCmdEvents("uname",
					0,
					1*time.Second,
					[]*pb.Event{
						expectPbEvent(anyHost, "uname", testutils.CPUForTests, anyPID, 0, events.SchedProcessExec, orPolNames("exec-event-2")),
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
		// {
		//   Disabled due to flaky behavior in some environments, see:
		//   https://github.com/aquasecurity/tracee/issues/4799#issuecomment-3018918112
		//
		// 	// This test is a bit tricky, as it relies on the environment where the test is run.
		// 	// The main goal is to ensure that at least one event coming from pid 0 (swapper) is captured.
		// 	name: "pid: event: data: trace event sched_switch with data from pid 0",
		// 	policyFiles: []testutils.PolicyFileWithID{
		// 		{
		// 			Id: 1,
		// 			PolicyFile: v1beta1.PolicyFile{
		// 				Metadata: v1beta1.Metadata{
		// 					Name: "pid-0-event-data",
		// 				},
		// 				Spec: k8s.PolicySpec{
		// 					Scope: []string{
		// 						"pid=0",
		// 					},
		// 					DefaultActions: []string{"log"},
		// 					Rules: []k8s.Rule{
		// 						{
		// 							Event:   "sched_switch",
		// 							Filters: []string{},
		// 						},
		// 					},
		// 				},
		// 			},
		// 		},
		// 	},
		// 	cmdEvents: []cmdEvents{
		// 		newCmdEvents(
		// 			// Do not execute any command; simply wait to capture background system activity (primarily from Tracee).
		// 			// During this waiting period, the system is expected to produce numerous 'sched_switch' events
		// 			// from the 'swapper' process (pid 0), even in minimal environments with only one CPU.
		// 			expectFromSystem,
		// 			100*time.Millisecond, // wait
		// 			0,                    // this value is ignored when 'expectFromSystem' is used
		// 			[]*pb.Event{
		// 				expectPbEvent(anyHost, anyComm, anyProcessorID, 0, 0, events.SchedSwitch, orPolNames("pid-0-event-data")),
		// 			},
		// 			[]string{},
		// 		),
		// 	},
		// 	useSyscaller: false,
		// 	coolDown:     1 * time.Second,
		// 	test:         ExpectAllEvtsEqualToOne,
		// },
		{
			name: "pid: trace events from pid 1",
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 1,
					PolicyFile: v1beta1.PolicyFile{
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
					[]*pb.Event{
						expectPbEvent(anyHost, "systemd", anyProcessorID, 1, 0, events.MemfdCreate, orPolNames("pid-1")),
						expectPbEvent(anyHost, "systemd", anyProcessorID, 1, 0, events.SecurityInodeUnlink, orPolNames("pid-1")),
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
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 1,
					PolicyFile: v1beta1.PolicyFile{
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
					[]*pb.Event{
						expectPbEvent(anyHost, "ls", testutils.CPUForTests, anyPID, 0, anyEventID, orPolNames("uid-0-comm")),
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
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 1,
					PolicyFile: v1beta1.PolicyFile{
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
					[]*pb.Event{}, // no events expected
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllInOrderSequentially,
		},
		{
			name: "comm: trace filesystem events from ls command",
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 1,
					PolicyFile: v1beta1.PolicyFile{
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
									Event:   "tag=fs", // fs tag (set)
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
					[]*pb.Event{
						expectPbEvent(anyHost, "ls", testutils.CPUForTests, anyPID, 0, anyEventID, orPolNames("event-fs")),
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
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 1,
					PolicyFile: v1beta1.PolicyFile{
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
					"docker run -d --rm "+busyboxImage,
					0,
					10*time.Second, // give some time for the container to start (possibly downloading the image)
					[]*pb.Event{
						// using anyComm as some versions of dockerd may result in e.g. "dockerd" or "exe"
						expectPbEvent(anyHost, anyComm, anyProcessorID, anyPID, 0, events.Setns, orPolNames("exec-event")),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAtLeastOneForEach,
		},
		{
			name: "pid: trace new (should be empty)",
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 1,
					PolicyFile: v1beta1.PolicyFile{
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
					[]*pb.Event{}, // no events expected
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllInOrderSequentially,
		},
		{
			name: "comm: trace events set in a specific policy from ls command",
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 64,
					PolicyFile: v1beta1.PolicyFile{
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
					[]*pb.Event{
						expectPbEvent(anyHost, "ls", testutils.CPUForTests, anyPID, 0, anyEventID, orPolNames("comm-64")),
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
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 64,
					PolicyFile: v1beta1.PolicyFile{
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
					Id: 42,
					PolicyFile: v1beta1.PolicyFile{
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
					[]*pb.Event{
						expectPbEvent(anyHost, "ls", testutils.CPUForTests, anyPID, 0, anyEventID, orPolNames("comm-64")),
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
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 64,
					PolicyFile: v1beta1.PolicyFile{
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
					Id: 42,
					PolicyFile: v1beta1.PolicyFile{
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
					[]*pb.Event{
						expectPbEvent(anyHost, "ls", testutils.CPUForTests, anyPID, 0, anyEventID, orPolNames("comm-64")),
					},
					[]string{},
				),
				newCmdEvents(
					"who",
					0,
					1*time.Second,
					[]*pb.Event{
						expectPbEvent(anyHost, "who", testutils.CPUForTests, anyPID, 0, anyEventID, orPolNames("comm-42")),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllEvtsEqualToOne,
		},
		{
			name: "event: data: context: only security_file_open from \"execve\" syscall",
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 42,
					PolicyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "event-data-context",
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
										"data.pathname=*/ls",
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
					[]*pb.Event{
						expectPbEvent(anyHost, "bash", // note that comm name is from the runner
							testutils.CPUForTests, anyPID, 0, events.SecurityFileOpen, orPolNames("event-data-context"), expectPbArg("pathname", "*/ls")),
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
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 42,
					PolicyFile: v1beta1.PolicyFile{
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
					[]*pb.Event{
						expectPbEvent(anyHost, "tee", testutils.CPUForTests, anyPID, 0, events.MagicWrite, orPolNames("comm-event")),
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
		// 	name: "comm: event: data: sign: trace sys events + signature events in separate policies",
		// 	policyFiles: []testutils.PolicyFileWithID{
		// 		{
		// 			Id: 3,
		// 			PolicyFile: v1beta1.PolicyFile{
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
		// 			Id: 5,
		// 			PolicyFile: v1beta1.PolicyFile{
		// 				Name:          "event-data",
		// 				Scope:         []string{},
		// 				DefaultActions: []string{"log"},
		// 				Rules: []k8s.Rule{
		// 					{
		// 						Event:  "ptrace",
		// 						Filters: []string{"data.pid=0"},
		// 					},
		// 				},
		// 			},
		// 		},
		// 		{
		// 			Id: 9,
		// 			PolicyFile: v1beta1.PolicyFile{
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
		// 			[]*pb.Event{
		// 				expectPbEvent(anyHost, "ping", testutils.CPUForTests, anyPID, 0, events.NetPacketICMP, orPolNames("comm-event")),
		// 			},
		// 			[]string{},
		// 		),
		// 		newCmdEvents(
		// 			"strace ls",
		// 			1*time.Second,
		// 			[]*pb.Event{
		// 				expectPbEvent(anyHost, "strace", testutils.CPUForTests, anyPID, 0, events.Ptrace, orPolNames("event-data")),
		// 				expectPbEvent(anyHost, "strace", testutils.CPUForTests, anyPID, 0, events.anti_debugging, orPolNames("sign")),
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
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 3,
					PolicyFile: v1beta1.PolicyFile{
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
					Id: 5,
					PolicyFile: v1beta1.PolicyFile{
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
					[]*pb.Event{
						expectPbEvent(anyHost, "ping", testutils.CPUForTests, anyPID, 0, events.NetPacketICMP, orPolNames("comm-event-3", "comm-event-5")),
						expectPbEvent(anyHost, "ping", testutils.CPUForTests, anyPID, 0, events.NetPacketICMP, orPolNames("comm-event-3", "comm-event-5")),
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
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 3,
					PolicyFile: v1beta1.PolicyFile{
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
					Id: 5,
					PolicyFile: v1beta1.PolicyFile{
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
					[]*pb.Event{
						expectPbEvent(anyHost, "ping", testutils.CPUForTests, anyPID, 0, events.Setuid, orPolNames("comm-event-5")),

						expectPbEvent(anyHost, "ping", testutils.CPUForTests, anyPID, 0, events.NetPacketICMP, orPolNames("comm-event-3", "comm-event-5")),
						expectPbEvent(anyHost, "ping", testutils.CPUForTests, anyPID, 0, events.NetPacketICMP, orPolNames("comm-event-3", "comm-event-5")),
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
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 3,
					PolicyFile: v1beta1.PolicyFile{
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
					Id: 5,
					PolicyFile: v1beta1.PolicyFile{
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
					Id: 7,
					PolicyFile: v1beta1.PolicyFile{
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
					Id: 9,
					PolicyFile: v1beta1.PolicyFile{
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
					[]*pb.Event{
						expectPbEvent(anyHost, "ping", testutils.CPUForTests, anyPID, 0, events.SchedProcessExec, orPolNames("comm-event-7", "comm-event-9")),

						expectPbEvent(anyHost, "ping", testutils.CPUForTests, anyPID, 0, events.SecuritySocketConnect, orPolNames("comm-event-9")),

						expectPbEvent(anyHost, "ping", testutils.CPUForTests, anyPID, 0, events.NetPacketICMP, orPolNames("comm-event-3", "comm-event-5")),
						expectPbEvent(anyHost, "ping", testutils.CPUForTests, anyPID, 0, events.NetPacketICMP, orPolNames("comm-event-3", "comm-event-5")),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllInOrderSequentially,
		},
		{
			name: "comm: event: trace events from nc command for net_tcp_connect event",
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 1,
					PolicyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "net-event-1",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=nc",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event:   "net_tcp_connect",
									Filters: []string{},
								},
							},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"bash -c 'nc -zv localhost 7777 || true'",
					0,
					2*time.Second,
					[]*pb.Event{
						expectPbEvent(
							anyHost, "nc", testutils.CPUForTests, anyPID, 0, events.NetTCPConnect, orPolNames("net-event-1")),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAtLeastOneForEach,
		},
		{
			name: "comm: trace only events from from ls and who commands in multiple policies",
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 64,
					PolicyFile: v1beta1.PolicyFile{
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
					Id: 42,
					PolicyFile: v1beta1.PolicyFile{
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
					[]*pb.Event{
						expectPbEvent(anyHost, "ls", testutils.CPUForTests, anyPID, 0, anyEventID, orPolNames("comm-64", "comm-42")),
					},
					[]string{},
				),
				newCmdEvents(
					"who",
					0,
					1*time.Second,
					[]*pb.Event{
						expectPbEvent(anyHost, "who", testutils.CPUForTests, anyPID, 0, anyEventID, orPolNames("comm-42")),
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
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 64,
					PolicyFile: v1beta1.PolicyFile{
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
					Id: 42,
					PolicyFile: v1beta1.PolicyFile{
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
					[]*pb.Event{
						expectPbEvent(anyHost, "ls", testutils.CPUForTests, anyPID, 0, anyEventID, orPolNames("comm-64", "comm-42")),
					},
					[]string{},
				),
				newCmdEvents(
					"who",
					0,
					1*time.Second,
					[]*pb.Event{
						expectPbEvent(anyHost, "who", testutils.CPUForTests, anyPID, 0, anyEventID, orPolNames("comm-42")),
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
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 1,
					PolicyFile: v1beta1.PolicyFile{
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
					5*time.Second,
					[]*pb.Event{
						expectPbEvent(anyHost, "fakeprog1", testutils.CPUForTests, anyPID, 0, events.Read, orPolNames("comm-event")),
						expectPbEvent(anyHost, "fakeprog1", testutils.CPUForTests, anyPID, 0, events.Write, orPolNames("comm-event")),
					},
					[]string{},
				),
			},
			useSyscaller: true,
			coolDown:     0,
			test:         ExpectAtLeastOneForEach, // syscaller might emit its own events, so we expect at least one of each
		},
		{
			name: "event: trace execve event set in a specific policy from fakeprog1 command",
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 42,
					PolicyFile: v1beta1.PolicyFile{
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
					5*time.Second, // increased timeout for CI environments
					[]*pb.Event{
						expectPbEvent(anyHost, "fakeprog1", testutils.CPUForTests, anyPID, 0, events.Execve, orPolNames("event-pol-42")),
					},
					[]string{},
				),
			},
			useSyscaller: true,
			coolDown:     0,
			test:         ExpectAtLeastOneForEach,
		},
		{
			name: "comm: event: data: trace event set in a specific policy with data from fakeprog1 and fakeprog2 commands",
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 64,
					PolicyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "comm-event-data-64",
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
										"data.dirfd=0",
										"data.flags=0",
										"data.mode=0",
									},
								},
							},
						},
					},
				},
				{
					Id: 42,
					PolicyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "comm-event-data-42",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=fakeprog2",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event: "read",
									Filters: []string{
										"data.fd=0",
										"data.buf=0",
										"data.count=0",
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
					5*time.Second, // increased timeout for CI environments
					[]*pb.Event{
						expectPbEvent(anyHost, "fakeprog1", testutils.CPUForTests, anyPID, 0, events.Openat, orPolNames("comm-event-data-64"),
							expectPbArg("dirfd", int32(0)),
							expectPbArg("flags", int32(0)),
							expectPbArg("mode", uint16(0)),
						),
					},
					[]string{},
				),
				newCmdEvents(
					"fakeprog2",
					0,
					5*time.Second, // increased timeout for CI environments
					[]*pb.Event{
						expectPbEvent(anyHost, "fakeprog2", testutils.CPUForTests, anyPID, 0, events.Read, orPolNames("comm-event-data-42"),
							expectPbArg("fd", int32(0)),
							expectPbArg("buf", trace.Pointer(0)),
							expectPbArg("count", uint64(0)),
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
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 64,
					PolicyFile: v1beta1.PolicyFile{
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
					Id: 42,
					PolicyFile: v1beta1.PolicyFile{
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
									Event: "openat",
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
					5*time.Second, // increased timeout for CI environments
					[]*pb.Event{
						expectPbEvent(anyHost, "fakeprog1", testutils.CPUForTests, anyPID, 0, events.Openat, orPolNames("comm-event-retval-64"),
							expectPbArg("dirfd", int32(0)),
							expectPbArg("flags", int32(0)),
							expectPbArg("mode", uint16(0)),
						),
					},
					[]string{},
				),
				newCmdEvents(
					"fakeprog2",
					100*time.Millisecond,
					5*time.Second, // increased timeout for CI environments
					[]*pb.Event{}, // no events expected
					[]string{},
				),
			},
			useSyscaller: true,
			coolDown:     0,
			test:         ExpectAllInOrderSequentially,
		},
		{
			name: "comm: event: data: trace event security_file_open set in multiple policies using multiple filter types",
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 1,
					PolicyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "sfo-pol-1",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=more",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event: "security_file_open",
									Filters: []string{
										"data.pathname=/etc/net*",
										"data.pathname=/etc/ld.so.cache",
										"data.pathname!=/usr/lib/*",
									},
								},
							},
						},
					},
				},
				{
					Id: 2,
					PolicyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "sfo-pol-2",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=more",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event: "security_file_open",
									Filters: []string{
										"data.pathname!=/etc/netconfig",
										"data.pathname!=/usr/lib/*",
										"data.pathname=*ld.so.cache",
									},
								},
							},
						},
					},
				},
				{
					Id: 3,
					PolicyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "sfo-pol-3",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=more",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event: "security_file_open",
									Filters: []string{
										"data.pathname!=/etc/ld.so.cache",
										"data.pathname!=*libtinfo.so.6.3",
										"data.pathname!=*libc.so.6",
									},
								},
							},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					// To test certain "not equal" filters, such as exact, prefix, and suffix,
					// it was necessary to use a fixed version of Ubuntu to ensure consistent
					// library versions.
					"docker run --rm "+ubuntuJammyPinnedImage+" more /etc/netconfig",
					0,
					20*time.Second,
					// Running the commands inside a container caused duplicate
					// security_file_open events to be generated. This is why the events are duplicated.
					[]*pb.Event{
						expectPbEvent(anyHost, "more", anyProcessorID, anyPID, 0, events.SecurityFileOpen, orPolNames("sfo-pol-1", "sfo-pol-2"), expectPbArg("pathname", "/etc/ld.so.cache")),
						expectPbEvent(anyHost, "more", anyProcessorID, anyPID, 0, events.SecurityFileOpen, orPolNames("sfo-pol-1", "sfo-pol-2"), expectPbArg("pathname", "/etc/ld.so.cache")),
						expectPbEvent(anyHost, "more", anyProcessorID, anyPID, 0, events.SecurityFileOpen, orPolNames("sfo-pol-1", "sfo-pol-3"), expectPbArg("pathname", "/etc/netconfig")),
						expectPbEvent(anyHost, "more", anyProcessorID, anyPID, 0, events.SecurityFileOpen, orPolNames("sfo-pol-1", "sfo-pol-3"), expectPbArg("pathname", "/etc/netconfig")),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllInOrderSequentially,
		},
		{
			name: "comm: event: data: trace event security_file_open and magic_write using multiple filter types combined",
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 1,
					PolicyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "sfo-mw-combined-pol-1",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=cat",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event: "security_file_open",
									Filters: []string{
										"data.pathname=/etc/ld.so.cache",
										"data.pathname=/etc/netconfig",
									},
								},
								{
									Event: "magic_write",
									Filters: []string{
										"data.pathname=/tmp/netconfig",
									},
								},
							},
						},
					},
				},
				{
					Id: 2,
					PolicyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "sfo-mw-combined-pol-2",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=cat",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event: "security_file_open",
									Filters: []string{
										"data.pathname=/etc/netconfig",
									},
								},
								{
									Event: "magic_write",
									Filters: []string{
										"data.pathname!=/tmp/netconfig",
									},
								},
							},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					// To test certain "not equal" filters, such as exact, prefix, and suffix,
					// it was necessary to use a fixed version of Ubuntu to ensure consistent
					// library versions.
					"docker run --rm "+ubuntuJammyPinnedImage+" sh -c 'cat /etc/netconfig > /tmp/netconfig'",
					0,
					20*time.Second,
					// Running the commands inside a container caused duplicate
					// security_file_open events to be generated. This is why the events are duplicated.
					[]*pb.Event{
						expectPbEvent(anyHost, "cat", anyProcessorID, anyPID, 0, events.SecurityFileOpen, orPolNames("sfo-mw-combined-pol-1"), expectPbArg("pathname", "/etc/ld.so.cache")),
						expectPbEvent(anyHost, "cat", anyProcessorID, anyPID, 0, events.SecurityFileOpen, orPolNames("sfo-mw-combined-pol-1"), expectPbArg("pathname", "/etc/ld.so.cache")),
						expectPbEvent(anyHost, "cat", anyProcessorID, anyPID, 0, events.SecurityFileOpen, orPolNames("sfo-mw-combined-pol-1", "sfo-mw-combined-pol-2"), expectPbArg("pathname", "/etc/netconfig")),
						expectPbEvent(anyHost, "cat", anyProcessorID, anyPID, 0, events.SecurityFileOpen, orPolNames("sfo-mw-combined-pol-1", "sfo-mw-combined-pol-2"), expectPbArg("pathname", "/etc/netconfig")),
						expectPbEvent(anyHost, "cat", anyProcessorID, anyPID, 0, events.MagicWrite, orPolNames("sfo-mw-combined-pol-1"), expectPbArg("pathname", "/tmp/netconfig")),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllInOrderSequentially,
		},
		{
			name: "comm: event: data: trace event magic_write set in multiple policies using multiple filter types",
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 1,
					PolicyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "mw-pol-1",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=more",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event: "magic_write",
									Filters: []string{
										"data.pathname=/tmp/*",
									},
								},
							},
						},
					},
				},
				{
					Id: 2,
					PolicyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "mw-pol-2",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=more",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event: "magic_write",
									Filters: []string{
										"data.pathname=/tmp/hostname",
										"data.pathname=*passwd",
									},
								},
							},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"sh -c 'more /etc/hostname > /tmp/hostname; more /etc/shadow > /tmp/shadow; more /etc/passwd > /tmp/passwd;'",
					0,
					1*time.Second,
					[]*pb.Event{
						expectPbEvent(anyHost, "more", testutils.CPUForTests, anyPID, 0, events.MagicWrite, orPolNames("mw-pol-1", "mw-pol-2"), expectPbArg("pathname", "/tmp/hostname")),
						expectPbEvent(anyHost, "more", testutils.CPUForTests, anyPID, 0, events.MagicWrite, orPolNames("mw-pol-1"), expectPbArg("pathname", "/tmp/shadow")),
						expectPbEvent(anyHost, "more", testutils.CPUForTests, anyPID, 0, events.MagicWrite, orPolNames("mw-pol-1", "mw-pol-2"), expectPbArg("pathname", "/tmp/passwd")),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAtLeastOneForEach,
		},
		{
			name: "comm: event: data: trace event security_file_open set in multiple policies (with and without in-kernel filter)",
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 1,
					PolicyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "sfo-pol-1",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=more",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event: "security_file_open",
									Filters: []string{
										"data.syscall_pathname=/sys/class/dmi/id*",
									},
								},
							},
						},
					},
				},
				{
					Id: 2,
					PolicyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "sfo-pol-2",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=more",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event: "security_file_open",
									Filters: []string{
										"data.pathname=/etc/pam.d/*",
									},
								},
							},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"more /sys/class/dmi/id/bios_date",
					0,
					1*time.Second,
					[]*pb.Event{
						expectPbEvent(anyHost, "more", testutils.CPUForTests, anyPID, 0, events.SecurityFileOpen, orPolNames("sfo-pol-1"), expectPbArg("syscall_pathname", "/sys/class/dmi/id/bios_date")),
					},
					[]string{},
				),
				newCmdEvents(
					"more /etc/pam.d/other",
					0,
					1*time.Second,
					[]*pb.Event{
						expectPbEvent(anyHost, "more", testutils.CPUForTests, anyPID, 0, events.SecurityFileOpen, orPolNames("sfo-pol-2"), expectPbArg("pathname", "/etc/pam.d/other")),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAtLeastOneForEach,
		},
		{
			name: "comm: event: data: trace event security_file_open set in multiple policies (with and without in-kernel filter) mixed in same policy",
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 1,
					PolicyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "sfo-pol-1",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=more",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event: "security_file_open",
									Filters: []string{
										"data.pathname=/sys/devices/virtual/dmi/id*",
										"data.syscall_pathname=/sys/class/dmi/id*",
									},
								},
							},
						},
					},
				},
				{
					Id: 2,
					PolicyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "sfo-pol-2",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=more",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event: "security_file_open",
									Filters: []string{
										"data.pathname=/etc/pam.d/*",
									},
								},
							},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"more /sys/class/dmi/id/bios_date",
					0,
					1*time.Second,
					[]*pb.Event{
						expectPbEvent(anyHost, "more", testutils.CPUForTests, anyPID, 0, events.SecurityFileOpen, orPolNames("sfo-pol-1"), expectPbArg("pathname", "/sys/devices/virtual/dmi/id/bios_date")),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAtLeastOneForEach,
		},
		{
			name: "comm: event: data: trace event security_mmap_file using multiple filter types",
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 1,
					PolicyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "smf-pol-1",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=ldd",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event: "security_mmap_file",
									Filters: []string{
										"data.pathname=/usr/bin/bash",
										"data.pathname=*ld.so.cache",
									},
								},
							},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"ldd /usr/bin/bash",
					0,
					1*time.Second,
					[]*pb.Event{
						expectPbEvent(anyHost, "ldd", testutils.CPUForTests, anyPID, 0, events.SecurityMmapFile, orPolNames("smf-pol-1"), expectPbArg("pathname", "/usr/bin/bash")),
						expectPbEvent(anyHost, "ldd", testutils.CPUForTests, anyPID, 0, events.SecurityMmapFile, orPolNames("smf-pol-1"), expectPbArg("pathname", "/etc/ld.so.cache")),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAtLeastOneForEach,
		},
		{
			name: "comm: event: data: trace event security_file_open and magic_write using multiple filter types",
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 1,
					PolicyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "sfo-mw-pol-1",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=more",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event: "security_file_open",
									Filters: []string{
										"data.pathname=/etc/host*",
									},
								},
								{
									Event: "magic_write",
									Filters: []string{
										"data.pathname=*shadow",
										"data.pathname=*passwd",
									},
								},
							},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"sh -c 'more /etc/hostname > /tmp/hostname; more /etc/shadow > /tmp/shadow; more /etc/passwd > /tmp/passwd;'",
					0,
					1*time.Second,
					[]*pb.Event{
						expectPbEvent(anyHost, "more", testutils.CPUForTests, anyPID, 0, events.SecurityFileOpen, orPolNames("sfo-mw-pol-1"), expectPbArg("pathname", "/etc/host*")),
						expectPbEvent(anyHost, "more", testutils.CPUForTests, anyPID, 0, events.MagicWrite, orPolNames("sfo-mw-pol-1"), expectPbArg("pathname", "*shadow")),
						expectPbEvent(anyHost, "more", testutils.CPUForTests, anyPID, 0, events.MagicWrite, orPolNames("sfo-mw-pol-1"), expectPbArg("pathname", "*passwd")),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAtLeastOneForEach,
		},
		{
			name: "comm: event: data: trace event with pathname exceeding 255 characters",
			policyFiles: []testutils.PolicyFileWithID{
				{
					Id: 1,
					PolicyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "sfo-pol-1",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=more",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event: "security_file_open",
									Filters: []string{
										"data.pathname=/tmp/AAAAAAAAAAAA*",
									},
								},
							},
						},
					},
				},
				{
					Id: 2,
					PolicyFile: v1beta1.PolicyFile{
						Metadata: v1beta1.Metadata{
							Name: "sfo-pol-2",
						},
						Spec: k8s.PolicySpec{
							Scope: []string{
								"comm=more",
							},
							DefaultActions: []string{"log"},
							Rules: []k8s.Rule{
								{
									Event: "security_file_open",
									Filters: []string{
										"data.pathname=*DEFGHIJK",
									},
								},
							},
						},
					},
				},
			},
			cmdEvents: []cmdEvents{
				newCmdEvents(
					"bash -c 'touch /tmp/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
						"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
						"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABCDEFGHIJK; more /tmp/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
						"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
						"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABCDEFGHIJK'",
					0,
					1*time.Second,
					[]*pb.Event{
						expectPbEvent(anyHost, "more", testutils.CPUForTests, anyPID, 0, events.SecurityFileOpen, orPolNames("sfo-pol-1", "sfo-pol-2"),
							expectPbArg("pathname", "/tmp/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
								"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
								"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABCDEFGHIJK")),
					},
					[]string{},
				),
			},
			useSyscaller: false,
			coolDown:     0,
			test:         ExpectAllInOrderSequentially,
		},
	}

	// run tests cases
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			// wait for the previous test to cool down
			coolDown(t, tc.coolDown)

			// prepare tracee traceeConfig
			traceeConfig := config.Config{
				Capabilities: &config.CapabilitiesConfig{
					BypassCaps: true,
				},
				Enrichment: nil, // Disable enrichment
			}
			ps := testutils.NewPolicies(tc.policyFiles)
			initialPolicies := make([]interface{}, 0, len(ps))
			for _, p := range ps {
				initialPolicies = append(initialPolicies, p)
			}
			traceeConfig.InitialPolicies = initialPolicies

			traceeTimeout := 60 * time.Second
			ctx, cancel := context.WithTimeout(context.Background(), traceeTimeout)
			defer func() {
				if ctx.Err() != nil {
					if ctx.Err() == context.DeadlineExceeded {
						t.Log("  Tracee timedout")
					} else {
						t.Logf("  %v", ctx.Err())
					}
				}
				cancel()
			}()

			// start tracee
			trc, err := testutils.StartTracee(ctx, t, traceeConfig, nil, nil)
			if err != nil {
				t.Fatal(err)
			}

			t.Log("  --- started tracee ---")
			err = testutils.WaitForTraceeStart(trc)
			if err != nil {
				t.Fatal(err)
			}

			stream, err := trc.Subscribe(config.Stream{})
			require.NoError(t, err)
			defer trc.Unsubscribe(stream)

			// start a goroutine to read events from the channel into the buffer
			buf := testutils.NewEventBuffer()
			go func(ctx context.Context, buf *testutils.EventBuffer) {
				for {
					select {
					case <-ctx.Done():
						return
					case pbEvent := <-stream.ReceiveEvents():
						if pbEvent != nil {
							buf.AddEvent(pbEvent)
						}
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
			errStop := testutils.WaitForTraceeStop(trc)
			if errStop != nil {
				t.Log(errStop)
				failed = true
			} else {
				t.Log("  --- stopped tracee ---")
			}

			if failed {
				t.Fail()
			}
		})
	}
}

const (
	expectFromSystem    = ""
	expectFromSystemPid = math.MaxInt

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
	policyFiles  []testutils.PolicyFileWithID
	cmdEvents    []cmdEvents
	useSyscaller bool
	coolDown     time.Duration // cool down before running the test case
	test         func(t *testing.T, cmdEvents []cmdEvents, actual *testutils.EventBuffer, useSyscaller bool) error
}

type cmdEvents struct {
	runCmd           string
	waitFor          time.Duration // time to wait before collecting events
	timeout          time.Duration // timeout for the command to run
	expectedEvents   []*pb.Event
	unexpectedEvents []*pb.Event
	sets             []string
}

// newCmdEvents is a helper function to create a cmdEvents
func newCmdEvents(runCmd string, waitFor, timeout time.Duration, evts []*pb.Event, sets []string) cmdEvents {
	return cmdEvents{
		runCmd:         runCmd,
		waitFor:        waitFor,
		timeout:        timeout,
		expectedEvents: evts,
		sets:           sets,
	}
}

// orPolIDs is a helper function to create a bit mask of the given policies IDs
// orPolNames is a helper function to create a slice of the given policies names
func orPolNames(policies ...string) []string {
	return policies
}

// expectPbEvent is a helper function to create a pb.Event for test expectations
// Use sentinel values (anyHost, anyComm, anyPID, etc.) for fields that should not be checked
func expectPbEvent(
	host, comm string,
	processorID, pid, uid int,
	eventID events.ID,
	matchPolNames []string,
	args ...*pb.EventValue,
) *pb.Event {
	event := &pb.Event{
		Name: events.Core.GetDefinitionByID(eventID).GetName(),
	}

	// Set event ID (translate to external ID)
	// Integration tests receive events from streams, which publish external IDs
	// (streams are at the external API boundary). Test expectations must match
	// the same ID format as actual events from streams.
	event.Id = events.TranslateEventID(int(eventID))

	// Set workload if any fields are specified
	if comm != anyComm || pid != anyPID || uid != anyUID || processorID != anyProcessorID {
		event.Workload = &pb.Workload{}

		if comm != anyComm || pid != anyPID || uid != anyUID {
			event.Workload.Process = &pb.Process{}

			// Set thread (comm)
			if comm != anyComm {
				event.Workload.Process.Thread = &pb.Thread{
					Name: comm,
				}
			}

			// Set PID
			if pid != anyPID {
				event.Workload.Process.Pid = wrapperspb.UInt32(uint32(pid))
			}

			// Set UID
			if uid != anyUID {
				event.Workload.Process.RealUser = &pb.User{
					Id: wrapperspb.UInt32(uint32(uid)),
				}
			}
		}
	}

	// Set policies
	if len(matchPolNames) > 0 && matchPolNames[0] != anyPolicyName {
		event.Policies = &pb.Policies{
			Matched: matchPolNames,
		}
	}

	// Set data (arguments)
	if len(args) > 0 {
		event.Data = args
	}

	return event
}

// expectPbArg is a helper function to create a pb.EventValue for argument expectations
func expectPbArg(name string, value interface{}) *pb.EventValue {
	ev := &pb.EventValue{
		Name: name,
	}

	switch v := value.(type) {
	case string:
		ev.Value = &pb.EventValue_Str{Str: v}
	case int:
		ev.Value = &pb.EventValue_Int32{Int32: int32(v)}
	case int32:
		ev.Value = &pb.EventValue_Int32{Int32: v}
	case int64:
		ev.Value = &pb.EventValue_Int64{Int64: v}
	case uint16:
		ev.Value = &pb.EventValue_UInt32{UInt32: uint32(v)}
	case uint32:
		ev.Value = &pb.EventValue_UInt32{UInt32: v}
	case uint64:
		ev.Value = &pb.EventValue_UInt64{UInt64: v}
	case trace.Pointer:
		ev.Value = &pb.EventValue_Pointer{Pointer: uint64(v)}
	case bool:
		ev.Value = &pb.EventValue_Bool{Bool: v}
	case []byte:
		ev.Value = &pb.EventValue_Bytes{Bytes: v}
	case []string:
		ev.Value = &pb.EventValue_StrArray{StrArray: &pb.StringArray{Value: v}}
	default:
		// For unsupported types, store as string representation
		ev.Value = &pb.EventValue_Str{Str: fmt.Sprintf("%v", v)}
	}

	return ev
}

// GetDataByName extracts an argument from pb.Event.Data by name
// Similar to trace.Event.GetArgumentByName() but for protobuf events
func GetDataByName(event *pb.Event, name string) (*pb.EventValue, error) {
	if event == nil || event.Data == nil {
		return nil, fmt.Errorf("data not found: %s", name)
	}

	for _, data := range event.Data {
		if data.Name == name {
			return data, nil
		}
	}

	return nil, fmt.Errorf("data not found: %s", name)
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
func runCmd(t *testing.T, cmd cmdEvents, expectedEvts int, actual *testutils.EventBuffer, useSyscaller, failOnTimeout bool) (proc, error) {
	var (
		pid int
		err error
	)

	if cmd.runCmd == expectFromSystem {
		pid = expectFromSystemPid

		t.Log("  >>> expect events from system")
	} else {
		if useSyscaller {
			formatCmdEvents(&cmd)
		}

		t.Logf("  >>> running: %s", cmd.runCmd)
		pid, err = testutils.ExecPinnedCmdWithTimeout(cmd.runCmd, cmd.timeout)
		if err != nil {
			return proc{}, err
		}
	}

	err = testutils.WaitForTraceeOutputEvents(t, cmd.waitFor, actual, expectedEvts, failOnTimeout)
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
func runCmds(t *testing.T, cmdEvents []cmdEvents, actual *testutils.EventBuffer, useSyscaller, failOnTimeout bool) ([]proc, int, error) {
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

		procs = append(procs, proc{pid, len(cmd.expectedEvents)})
		expectedEvts += len(cmd.expectedEvents)
		waitForAverage += cmd.waitFor
	}
	if waitForAverage > 0 {
		waitForAverage /= time.Duration(len(cmdEvents))
	}

	err := testutils.WaitForTraceeOutputEvents(t, waitForAverage, actual, expectedEvts, failOnTimeout)
	if err != nil {
		return nil, 0, err
	}

	return procs, expectedEvts, nil
}

// formatCmdEvents formats given commands to be executed by syscaller helper tool
func formatCmdEvents(cmd *cmdEvents) {
	syscallerAbsPath := filepath.Join("..", "..", "dist", "syscaller")
	cmd.runCmd = fmt.Sprintf("%s %s", syscallerAbsPath, cmd.runCmd)

	for _, evt := range cmd.expectedEvents {
		// syscaller expects internal event IDs (actual syscall numbers on AMD64)
		// evt.Id contains external protobuf IDs, so we need to reverse-translate
		// by looking up the event definition by name
		eventDef := events.Core.GetDefinitionByName(evt.Name)
		if eventDef.NotValid() {
			panic(fmt.Sprintf("event definition not found for %s", evt.Name))
		}
		internalID := eventDef.GetID()
		cmd.runCmd = fmt.Sprintf("%s %d", cmd.runCmd, int(internalID))
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
func pidToCheck(cmd string, actEvt *pb.Event, expectedPid int) int {
	switch expectedPid {
	case 0, 1, 2: // special pids: 0 swapper, 1 systemd, 2 kthreadd
		return expectedPid
	}

	var actualPid int
	var parentPid int

	if actEvt.Workload != nil && actEvt.Workload.Process != nil {
		if actEvt.Workload.Process.Pid != nil {
			actualPid = int(actEvt.Workload.Process.Pid.Value)
		}
		if len(actEvt.Workload.Process.Ancestors) > 0 && actEvt.Workload.Process.Ancestors[0].Pid != nil {
			parentPid = int(actEvt.Workload.Process.Ancestors[0].Pid.Value)
		}
	}

	if isCmdAShellRunner(cmd) {
		// For shell commands, try to match the expected PID directly first
		if actualPid == expectedPid {
			return actualPid
		}
		// Otherwise, use parent PID (for child processes or fallback)
		return parentPid
	}

	return actualPid
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
func ExpectAtLeastOneForEach(t *testing.T, cmdEvents []cmdEvents, actual *testutils.EventBuffer, useSyscaller bool) error {
	for _, cmd := range cmdEvents {
		syscallsInSets := []string{}
		checkSets := len(cmd.sets) > 0
		if checkSets {
			syscallsInSets = getAllSyscallsInSets(cmd.sets)
		}

		actual.Clear()
		// first stage: run commands
		proc, err := runCmd(t, cmd, len(cmd.expectedEvents), actual, useSyscaller, true)
		if err != nil {
			return err
		}
		if len(cmd.expectedEvents) == 0 && proc.expectedEvts > 0 {
			return fmt.Errorf(
				"expected no events for command %s, but got %d",
				cmd.runCmd,
				proc.expectedEvts,
			)
		}

		actEvtsCopy := actual.GetCopy()

		findEventInResults := func(expEvt *pb.Event) (bool, error) {
			// Extract expected values (initialize to "any" sentinels)
			expComm := anyComm
			expPID := anyPID
			expUID := anyUID
			var expPolicies []string

			if expEvt.Workload != nil && expEvt.Workload.Process != nil {
				if expEvt.Workload.Process.Thread != nil {
					expComm = expEvt.Workload.Process.Thread.Name
				}
				if expEvt.Workload.Process.Pid != nil {
					expPID = int(expEvt.Workload.Process.Pid.Value)
				}
				if expEvt.Workload.Process.RealUser != nil && expEvt.Workload.Process.RealUser.Id != nil {
					expUID = int(expEvt.Workload.Process.RealUser.Id.Value)
				}
			}
			if expEvt.Policies != nil {
				expPolicies = expEvt.Policies.Matched
			}

			checkComm := expComm != anyComm
			checkPID := expPID != anyPID
			checkUID := expUID != anyUID
			checkEventID := expEvt.Id != pb.EventId(anyEventID)
			checkPolicyName := len(expPolicies) > 0 && expPolicies[0] != anyPolicyName

			for _, actEvt := range actEvtsCopy {
				if checkSets && !isInSets(actEvt.Name, syscallsInSets) {
					continue
				}

				// Check comm
				if checkComm {
					actComm := ""
					if actEvt.Workload != nil && actEvt.Workload.Process != nil && actEvt.Workload.Process.Thread != nil {
						actComm = actEvt.Workload.Process.Thread.Name
					}
					if actComm != expComm {
						continue
					}
				}

				// Check PID
				if checkPID {
					actPID := 0
					if actEvt.Workload != nil && actEvt.Workload.Process != nil && actEvt.Workload.Process.Pid != nil {
						actPID = int(actEvt.Workload.Process.Pid.Value)
					}
					if pidToCheck(cmd.runCmd, actEvt, expPID) != expPID {
						continue
					}
					if actPID != expPID {
						continue
					}
				}

				// Check UID
				if checkUID {
					actUID := 0
					if actEvt.Workload != nil && actEvt.Workload.Process != nil && actEvt.Workload.Process.RealUser != nil && actEvt.Workload.Process.RealUser.Id != nil {
						actUID = int(actEvt.Workload.Process.RealUser.Id.Value)
					}
					if actUID != expUID {
						continue
					}
				}

				// Check EventID
				if checkEventID && actEvt.Id != expEvt.Id {
					continue
				}

				// Check policy names
				if checkPolicyName {
					actPolicies := []string{}
					if actEvt.Policies != nil {
						actPolicies = actEvt.Policies.Matched
					}

					polNameFound := false
					for _, policyName := range expPolicies {
						for _, actPolicyName := range actPolicies {
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
				for _, expArg := range expEvt.Data {
					actArg, err := GetDataByName(actEvt, expArg.Name)
					if err != nil {
						return false, err
					}

					// Compare based on expected type
					switch expVal := expArg.Value.(type) {
					case *pb.EventValue_Str:
						actVal, ok := actArg.Value.(*pb.EventValue_Str)
						if !ok {
							return false, errors.New("failed to cast arg's value to string")
						}
						// Handle wildcard matching
						if strings.Contains(expVal.Str, "*") {
							pattern := strings.ReplaceAll(expVal.Str, "*", "")
							if !strings.Contains(actVal.Str, pattern) {
								continue
							}
						} else {
							if expVal.Str != actVal.Str {
								continue
							}
						}
					default:
						if !assert.ObjectsAreEqual(expArg.Value, actArg.Value) {
							continue
						}
					}
				}
				// if we got here, it means we found a match and can stop searching
				return true, nil
			}
			return false, nil
		}

		// second stage: validate events
		for _, expEvt := range cmd.expectedEvents {
			if len(cmd.expectedEvents) > 0 && proc.expectedEvts == 0 {
				return fmt.Errorf("expected events for command %s, but got none", cmd.runCmd)
			}
			found, err := findEventInResults(expEvt)
			if err != nil {
				return err
			}
			if !found {
				return fmt.Errorf(
					"Event %+v:\nnot found in actual output:\n%+v",
					expEvt,
					actEvtsCopy,
				)
			}
		}

		for _, expEvt := range cmd.unexpectedEvents {
			if len(cmd.expectedEvents) > 0 && proc.expectedEvts == 0 {
				return fmt.Errorf("expected events for command %s, but got none", cmd.runCmd)
			}
			found, err := findEventInResults(expEvt)
			if err != nil {
				return err
			}
			if found {
				return fmt.Errorf(
					"Event %+v:\nfound in actual output but was not expected:\n%+v",
					expEvt,
					actEvtsCopy,
				)
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
func ExpectAnyOfEvts(t *testing.T, cmdEvents []cmdEvents, actual *testutils.EventBuffer, useSyscaller bool) error {
	for _, cmd := range cmdEvents {
		if len(cmd.expectedEvents) <= 1 {
			return fmt.Errorf("ExpectAnyOfEvts test requires at least 2 expected events for command %s", cmd.runCmd)
		}

		syscallsInSets := []string{}
		checkSets := len(cmd.sets) > 0
		if checkSets {
			syscallsInSets = getAllSyscallsInSets(cmd.sets)
		}

		actual.Clear()
		// first stage: run commands
		proc, err := runCmd(t, cmd, 1, actual, useSyscaller, true)
		if err != nil {
			return err
		}

		actEvtsCopy := actual.GetCopy()

		// second stage: validate events
		found := false
		for _, expEvt := range cmd.expectedEvents {
			// Extract expected values (initialize to "any" sentinels)
			expComm := anyComm
			expPID := anyPID
			expUID := anyUID
			var expPolicies []string

			if expEvt.Workload != nil && expEvt.Workload.Process != nil {
				if expEvt.Workload.Process.Thread != nil {
					expComm = expEvt.Workload.Process.Thread.Name
				}
				if expEvt.Workload.Process.Pid != nil {
					expPID = int(expEvt.Workload.Process.Pid.Value)
				}
				if expEvt.Workload.Process.RealUser != nil && expEvt.Workload.Process.RealUser.Id != nil {
					expUID = int(expEvt.Workload.Process.RealUser.Id.Value)
				}
			}
			if expEvt.Policies != nil {
				expPolicies = expEvt.Policies.Matched
			}

			checkComm := expComm != anyComm
			checkPID := expPID != anyPID
			checkUID := expUID != anyUID
			checkEventID := expEvt.Id != pb.EventId(anyEventID)
			checkPolicyName := len(expPolicies) > 0 && expPolicies[0] != anyPolicyName

			if len(cmd.expectedEvents) > 0 && proc.expectedEvts == 0 {
				return fmt.Errorf("expected events for command %s, but got none", cmd.runCmd)
			}

			for _, actEvt := range actEvtsCopy {
				if checkSets && !isInSets(actEvt.Name, syscallsInSets) {
					continue
				}

				// Check comm
				if checkComm {
					actComm := ""
					if actEvt.Workload != nil && actEvt.Workload.Process != nil && actEvt.Workload.Process.Thread != nil {
						actComm = actEvt.Workload.Process.Thread.Name
					}
					if actComm != expComm {
						continue
					}
				}

				// Check PID
				if checkPID {
					actPID := 0
					if actEvt.Workload != nil && actEvt.Workload.Process != nil && actEvt.Workload.Process.Pid != nil {
						actPID = int(actEvt.Workload.Process.Pid.Value)
					}
					if pidToCheck(cmd.runCmd, actEvt, expPID) != expPID {
						continue
					}
					if actPID != expPID {
						continue
					}
				}

				// Check UID
				if checkUID {
					actUID := 0
					if actEvt.Workload != nil && actEvt.Workload.Process != nil && actEvt.Workload.Process.RealUser != nil && actEvt.Workload.Process.RealUser.Id != nil {
						actUID = int(actEvt.Workload.Process.RealUser.Id.Value)
					}
					if actUID != expUID {
						continue
					}
				}

				// Check EventID
				if checkEventID && actEvt.Id != expEvt.Id {
					continue
				}

				// Check policy names
				if checkPolicyName {
					actPolicies := []string{}
					if actEvt.Policies != nil {
						actPolicies = actEvt.Policies.Matched
					}

					polNameFound := false
					for _, policyName := range expPolicies {
						for _, actPolicyName := range actPolicies {
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
				for _, expArg := range expEvt.Data {
					actArg, err := GetDataByName(actEvt, expArg.Name)
					if err != nil {
						return err
					}

					// Compare based on expected type
					switch expVal := expArg.Value.(type) {
					case *pb.EventValue_Str:
						actVal, ok := actArg.Value.(*pb.EventValue_Str)
						if !ok {
							return errors.New("failed to cast arg's value to string")
						}
						// Handle wildcard matching
						if strings.Contains(expVal.Str, "*") {
							pattern := strings.ReplaceAll(expVal.Str, "*", "")
							if !strings.Contains(actVal.Str, pattern) {
								continue
							}
						} else {
							if expVal.Str != actVal.Str {
								continue
							}
						}
					default:
						if !assert.ObjectsAreEqual(expArg.Value, actArg.Value) {
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
			return fmt.Errorf("none of the expected events\n%+v\nare in the actual output\n%+v", cmd.expectedEvents, actEvtsCopy)
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
func ExpectAllEvtsEqualToOne(t *testing.T, cmdEvents []cmdEvents, actual *testutils.EventBuffer, useSyscaller bool) error {
	for _, cmd := range cmdEvents {
		if len(cmd.expectedEvents) != 1 {
			return fmt.Errorf("ExpectAllEvtsEqualToOne test requires exactly one event per command, but got %d events for command %s", len(cmd.expectedEvents), cmd.runCmd)
		}

		actual.Clear()
		// first stage: run commands
		proc, err := runCmd(t, cmd, len(cmd.expectedEvents), actual, useSyscaller, true)
		if err != nil {
			return err
		}

		actEvtsCopy := actual.GetCopy()

		if proc.expectedEvts == 0 {
			return fmt.Errorf("expected one event for command %s, but got none", cmd.runCmd)
		}
		syscallsInSets := []string{}
		checkSets := len(cmd.sets) > 0
		if checkSets {
			syscallsInSets = getAllSyscallsInSets(cmd.sets)
		}

		// second stage: validate events
		for _, expEvt := range cmd.expectedEvents {
			// Extract expected values (initialize to "any" sentinels)
			expComm := anyComm
			expPID := anyPID
			expUID := anyUID
			var expPolicies []string

			if expEvt.Workload != nil && expEvt.Workload.Process != nil {
				if expEvt.Workload.Process.Thread != nil {
					expComm = expEvt.Workload.Process.Thread.Name
				}
				if expEvt.Workload.Process.Pid != nil {
					expPID = int(expEvt.Workload.Process.Pid.Value)
				}
				if expEvt.Workload.Process.RealUser != nil && expEvt.Workload.Process.RealUser.Id != nil {
					expUID = int(expEvt.Workload.Process.RealUser.Id.Value)
				}
			}
			if expEvt.Policies != nil {
				expPolicies = expEvt.Policies.Matched
			}

			// Fix race condition: when anyPID is used, replace it with actual PID from launched process
			expectedPID := expPID
			if expectedPID == anyPID {
				expectedPID = proc.pid
			}

			checkComm := expComm != anyComm
			checkPID := expPID != anyPID // Always check PID now that anyPID has been replaced
			checkUID := expUID != anyUID
			checkEventID := expEvt.Id != pb.EventId(anyEventID)
			checkPolicyName := len(expPolicies) > 0 && expPolicies[0] != anyPolicyName

			for _, actEvt := range actEvtsCopy {
				if checkSets && !isInSets(actEvt.Name, syscallsInSets) {
					return fmt.Errorf("Event %s not found in sets %v", actEvt.Name, cmd.sets)
				}

				// Check comm
				if checkComm {
					actComm := ""
					if actEvt.Workload != nil && actEvt.Workload.Process != nil && actEvt.Workload.Process.Thread != nil {
						actComm = actEvt.Workload.Process.Thread.Name
					}
					if !assert.ObjectsAreEqual(expComm, actComm) {
						return fmt.Errorf("Event %+v:\ncomm mismatch: expected %s, got %s", actEvt, expComm, actComm)
					}
				}

				// Check PID
				if checkPID {
					actPID := pidToCheck(cmd.runCmd, actEvt, expectedPID)
					if !assert.ObjectsAreEqual(expectedPID, actPID) {
						return fmt.Errorf("Event %+v:\npid mismatch: expected %d, got %d", actEvt, expectedPID, actPID)
					}
				}

				// Check UID
				if checkUID {
					actUID := 0
					if actEvt.Workload != nil && actEvt.Workload.Process != nil && actEvt.Workload.Process.RealUser != nil && actEvt.Workload.Process.RealUser.Id != nil {
						actUID = int(actEvt.Workload.Process.RealUser.Id.Value)
					}
					if !assert.ObjectsAreEqual(expUID, actUID) {
						return fmt.Errorf("Event %+v:\nuser Id mismatch: expected %d, got %d", actEvt, expUID, actUID)
					}
				}

				// Check EventID
				if checkEventID && !assert.ObjectsAreEqual(expEvt.Id, actEvt.Id) {
					return fmt.Errorf("Event %+v:\nevent Id mismatch: expected %d, got %d", actEvt, expEvt.Id, actEvt.Id)
				}

				// Check policy names
				if checkPolicyName {
					actPolicies := []string{}
					if actEvt.Policies != nil {
						actPolicies = actEvt.Policies.Matched
					}
					if !assertUnorderedStringSlicesEqual(expPolicies, actPolicies) {
						return fmt.Errorf("Event %+v:\nmatched policies mismatch: expected %v, got %v", actEvt, expPolicies, actPolicies)
					}
				}

				// check args
				for _, expArg := range expEvt.Data {
					actArg, err := GetDataByName(actEvt, expArg.Name)
					if err != nil {
						return err
					}

					// Compare based on expected type
					switch expVal := expArg.Value.(type) {
					case *pb.EventValue_Str:
						actVal, ok := actArg.Value.(*pb.EventValue_Str)
						if !ok {
							return errors.New("failed to cast arg's value to string")
						}
						// Handle wildcard matching
						if strings.Contains(expVal.Str, "*") {
							pattern := strings.ReplaceAll(expVal.Str, "*", "")
							if !strings.Contains(actVal.Str, pattern) {
								return fmt.Errorf("Event %+v:\narg value mismatch: expected %s (type %T), got %s (type %T)", actEvt, pattern, pattern, actVal.Str, actVal.Str)
							}
						} else {
							if !assert.ObjectsAreEqual(expVal.Str, actVal.Str) {
								return fmt.Errorf("Event %+v:\narg value mismatch: expected %s (type %T), got %s (type %T)", actEvt, expVal.Str, expVal.Str, actVal.Str, actVal.Str)
							}
						}
					default:
						if !assert.ObjectsAreEqual(expArg.Value, actArg.Value) {
							return fmt.Errorf("Event %+v:\narg value mismatch: expected %v (type %T), got %v (type %T)", actEvt, expArg.Value, expArg.Value, actArg.Value, actArg.Value)
						}
					}
				}
			}
		}
	}

	return nil
}

// ExpectAllInOrderSequentially validates that the actual events match the
// expected events for each command, with events appearing in the same order of the
// expected events.
func ExpectAllInOrderSequentially(t *testing.T, cmdEvents []cmdEvents, actual *testutils.EventBuffer, useSyscaller bool) error {
	// first stage: run commands
	actual.Clear()
	procs, _, err := runCmds(t, cmdEvents, actual, useSyscaller, true)
	if err != nil {
		return err
	}
	if len(procs) > len(cmdEvents) {
		return fmt.Errorf("expected %d commands, but got %d", len(cmdEvents), len(procs))
	}

	actEvtsCopy := actual.GetCopy()

	actEvtIdx := 0
	// second stage: check events
	for _, cmd := range cmdEvents {
		syscallsInSets := []string{}
		checkSets := len(cmd.sets) > 0
		if checkSets {
			syscallsInSets = getAllSyscallsInSets(cmd.sets)
		}

		// compare the expected events with the actual events in the same order
		for _, expEvt := range cmd.expectedEvents {
			if actEvtIdx >= len(actEvtsCopy) {
				return fmt.Errorf("Event %+v:\nnot found or in wrong order in actual output:\n%+v", expEvt, actEvtsCopy)
			}
			actEvt := actEvtsCopy[actEvtIdx]
			actEvtIdx++

			if checkSets && !isInSets(actEvt.Name, syscallsInSets) {
				return fmt.Errorf("Event %s not found in sets %v", actEvt.Name, cmd.sets)
			}

			// Extract expected values (initialize to "any" sentinels)
			expComm := anyComm
			expPID := anyPID
			expUID := anyUID
			var expPolicies []string

			if expEvt.Workload != nil && expEvt.Workload.Process != nil {
				if expEvt.Workload.Process.Thread != nil {
					expComm = expEvt.Workload.Process.Thread.Name
				}
				if expEvt.Workload.Process.Pid != nil {
					expPID = int(expEvt.Workload.Process.Pid.Value)
				}
				if expEvt.Workload.Process.RealUser != nil && expEvt.Workload.Process.RealUser.Id != nil {
					expUID = int(expEvt.Workload.Process.RealUser.Id.Value)
				}
			}
			if expEvt.Policies != nil {
				expPolicies = expEvt.Policies.Matched
			}

			checkComm := expComm != anyComm
			checkPID := expPID != anyPID
			checkUID := expUID != anyUID
			checkEventID := expEvt.Id != pb.EventId(anyEventID)
			checkPolicyName := len(expPolicies) > 0 && expPolicies[0] != anyPolicyName

			// Check comm
			if checkComm {
				actComm := ""
				if actEvt.Workload != nil && actEvt.Workload.Process != nil && actEvt.Workload.Process.Thread != nil {
					actComm = actEvt.Workload.Process.Thread.Name
				}
				if !assert.ObjectsAreEqual(expComm, actComm) {
					return fmt.Errorf("Event %+v:\ncomm mismatch: expected %s, got %s", actEvt, expComm, actComm)
				}
			}

			// Check PID
			if checkPID {
				actPID := pidToCheck(cmd.runCmd, actEvt, expPID)
				if !assert.ObjectsAreEqual(expPID, actPID) {
					return fmt.Errorf("Event %+v:\npid mismatch: expected %d, got %d", actEvt, expPID, actPID)
				}
			}

			// Check UID
			if checkUID {
				actUID := 0
				if actEvt.Workload != nil && actEvt.Workload.Process != nil && actEvt.Workload.Process.RealUser != nil && actEvt.Workload.Process.RealUser.Id != nil {
					actUID = int(actEvt.Workload.Process.RealUser.Id.Value)
				}
				if !assert.ObjectsAreEqual(expUID, actUID) {
					return fmt.Errorf("Event %+v:\nuser Id mismatch: expected %d, got %d", actEvt, expUID, actUID)
				}
			}

			// Check EventID
			if checkEventID && !assert.ObjectsAreEqual(expEvt.Id, actEvt.Id) {
				return fmt.Errorf("Event %+v:\nevent Id mismatch: expected %d, got %d", actEvt, expEvt.Id, actEvt.Id)
			}

			// Check policy names
			if checkPolicyName {
				actPolicies := []string{}
				if actEvt.Policies != nil {
					actPolicies = actEvt.Policies.Matched
				}
				if !assertUnorderedStringSlicesEqual(expPolicies, actPolicies) {
					return fmt.Errorf("Event %+v:\nmatched policies mismatch: expected %v, got %v", actEvt, expPolicies, actPolicies)
				}
			}

			// check args
			for _, expArg := range expEvt.Data {
				actArg, err := GetDataByName(actEvt, expArg.Name)
				if err != nil {
					return err
				}

				// Compare based on expected type
				switch expVal := expArg.Value.(type) {
				case *pb.EventValue_Str:
					actVal, ok := actArg.Value.(*pb.EventValue_Str)
					if !ok {
						return errors.New("failed to cast arg's value to string")
					}
					// Handle wildcard matching
					if strings.Contains(expVal.Str, "*") {
						pattern := strings.ReplaceAll(expVal.Str, "*", "")
						if !strings.Contains(actVal.Str, pattern) {
							return fmt.Errorf("Event %+v:\narg value mismatch: expected %s (type %T), got %s (type %T)", actEvt, pattern, pattern, actVal.Str, actVal.Str)
						}
					} else {
						if !assert.ObjectsAreEqual(expVal.Str, actVal.Str) {
							return fmt.Errorf("Event %+v:\narg value mismatch: expected %s (type %T), got %s (type %T)", actEvt, expVal.Str, expVal.Str, actVal.Str, actVal.Str)
						}
					}

				default:
					if !assert.ObjectsAreEqual(expArg.Value, actArg.Value) {
						return fmt.Errorf("Event %+v:\narg value mismatch: expected %v (type %T), got %v (type %T)", actEvt, expArg.Value, expArg.Value, actArg.Value, actArg.Value)
					}
				}
			}
		}
	}

	return nil
}

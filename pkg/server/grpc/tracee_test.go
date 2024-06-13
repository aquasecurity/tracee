package grpc

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

func Test_convertEventWithProcessContext(t *testing.T) {
	t.Parallel()

	unixTime := int(time.Now().UnixNano())

	traceEvent := trace.Event{
		Timestamp:           unixTime,
		ThreadStartTime:     unixTime,
		ProcessID:           1,
		ThreadID:            2,
		HostProcessID:       3,
		HostThreadID:        4,
		ParentProcessID:     5,
		HostParentProcessID: 6,
		UserID:              7,
		ProcessName:         "processTest",
		EventID:             int(events.Execve),
		EventName:           "eventTest",
		MatchedPolicies:     []string{"policyTest"},
		Syscall:             "syscall",
		ContextFlags:        trace.ContextFlags{ContainerStarted: true},
		ThreadEntityId:      9,
		ProcessEntityId:     10,
		ParentEntityId:      11,
	}

	protoEvent, err := convertTraceeEventToProto(traceEvent)
	assert.NoError(t, err)

	assert.Equal(t, uint32(1), protoEvent.Context.Process.Pid.Value)
	assert.Equal(t, uint32(2), protoEvent.Context.Process.Thread.Tid.Value)
	assert.Equal(t, uint32(3), protoEvent.Context.Process.HostPid.Value)
	assert.Equal(t, uint32(4), protoEvent.Context.Process.Thread.HostTid.Value)
	assert.Equal(t, uint32(5), protoEvent.Context.Process.Ancestors[0].Pid.Value)
	assert.Equal(t, uint32(6), protoEvent.Context.Process.Ancestors[0].HostPid.Value)
	assert.Equal(t, uint32(7), protoEvent.Context.Process.RealUser.Id.Value)
	assert.Equal(t, pb.EventId_execve, protoEvent.Id)
	assert.Equal(t, uint32(9), protoEvent.Context.Process.Thread.UniqueId.Value)
	assert.Equal(t, uint32(10), protoEvent.Context.Process.UniqueId.Value)
	assert.Equal(t, uint32(11), protoEvent.Context.Process.Ancestors[0].UniqueId.Value)
	assert.Equal(t, "eventTest", protoEvent.Name)
	assert.Equal(t, []string{"policyTest"}, protoEvent.Policies.Matched)
	assert.Equal(t, "processTest", protoEvent.Context.Process.Thread.Name)
	assert.Equal(t, "syscall", protoEvent.Context.Process.Thread.Syscall)
	assert.Equal(t, true, protoEvent.Context.Process.Thread.Compat)
}

func Test_convertEventWithStackaddresses(t *testing.T) {
	t.Parallel()

	traceEvent := trace.Event{
		StackAddresses: []uint64{1, 2, 3},
	}

	protoEvent, err := convertTraceeEventToProto(traceEvent)
	assert.NoError(t, err)

	expected := []*pb.StackAddress{
		{Address: 1},
		{Address: 2},
		{Address: 3},
	}

	for i := range expected {
		assert.Equal(t, expected[i].Address, protoEvent.Context.Process.Thread.UserStackTrace.Addresses[i].Address)
	}
}

func Test_convertEventWithContainerContext(t *testing.T) {
	t.Parallel()

	traceEvent := trace.Event{
		Container: trace.Container{
			ID:          "containerID",
			Name:        "containerName",
			ImageName:   "imageName",
			ImageDigest: "imageDigest",
		},
	}

	protoEvent, err := convertTraceeEventToProto(traceEvent)
	assert.NoError(t, err)

	assert.Equal(t, "containerID", protoEvent.Context.Container.Id)
	assert.Equal(t, "containerName", protoEvent.Context.Container.Name)
	assert.Equal(t, "imageName", protoEvent.Context.Container.Image.Name)
	assert.Equal(t, []string{"imageDigest"}, protoEvent.Context.Container.Image.RepoDigests)
}

func Test_convertEventWithK8sContext(t *testing.T) {
	t.Parallel()

	traceEvent := trace.Event{
		Kubernetes: trace.Kubernetes{
			PodName:      "podName",
			PodNamespace: "podNamespace",
			PodUID:       "podUID",
		},
	}

	protoEvent, err := convertTraceeEventToProto(traceEvent)
	assert.NoError(t, err)

	assert.Equal(t, "podName", protoEvent.Context.K8S.Pod.Name)
	assert.Equal(t, "podNamespace", protoEvent.Context.K8S.Namespace.Name)
	assert.Equal(t, "podUID", protoEvent.Context.K8S.Pod.Uid)
}

func Test_convertEventWithThreat(t *testing.T) {
	t.Parallel()

	traceEvent := trace.Event{
		Metadata: &trace.Metadata{
			Description: "An attempt to abuse the Docker UNIX ..",
			Properties: map[string]interface{}{
				"Severity":    2,
				"Category":    "privilege-escalation",
				"Technique":   "Exploitation for Privilege Escalation",
				"external_id": "T1068",
			},
		},
	}

	protoEvent, err := convertTraceeEventToProto(traceEvent)
	assert.NoError(t, err)

	assert.Equal(t, "An attempt to abuse the Docker UNIX ..", protoEvent.Threat.Description)
	assert.Equal(t, "privilege-escalation", protoEvent.Threat.Mitre.Tactic.Name)
	assert.Equal(t, "Exploitation for Privilege Escalation", protoEvent.Threat.Mitre.Technique.Name)
	assert.Equal(t, "T1068", protoEvent.Threat.Mitre.Technique.Id)
}

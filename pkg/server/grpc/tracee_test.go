package grpc

import (
	"testing"
	"time"

	"gotest.tools/assert"

	pb "github.com/aquasecurity/tracee/types/api/v1beta1"
	"github.com/aquasecurity/tracee/types/trace"
)

func Test_convertEventWithProcessContext(t *testing.T) {
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
		EventID:             8,
		EventName:           "eventTest",
		MatchedPolicies:     []string{"policyTest"},
		Syscall:             "syscall",
		ContextFlags:        trace.ContextFlags{ContainerStarted: true},
		EntityID:            9,
	}

	protoEvent := convertTraceeEventToProto(traceEvent)

	assert.Equal(t, uint32(1), protoEvent.Context.Process.NamespacedPid.Value)
	assert.Equal(t, uint32(2), protoEvent.Context.Process.Thread.NamespacedTid.Value)
	assert.Equal(t, uint32(3), protoEvent.Context.Process.Pid.Value)
	assert.Equal(t, uint32(4), protoEvent.Context.Process.Thread.Tid.Value)
	assert.Equal(t, uint32(5), protoEvent.Context.Process.Parent.NamespacedPid.Value)
	assert.Equal(t, uint32(6), protoEvent.Context.Process.Parent.Pid.Value)
	assert.Equal(t, uint32(7), protoEvent.Context.Process.RealUser.Id.Value)
	assert.Equal(t, uint32(8), protoEvent.Id)
	assert.Equal(t, uint32(9), protoEvent.Context.Process.EntityId.Value)
	assert.Equal(t, "eventTest", protoEvent.Name)
	assert.DeepEqual(t, []string{"policyTest"}, protoEvent.Policies.Matched)
	assert.Equal(t, "processTest", protoEvent.Context.Process.Thread.Name)
	assert.Equal(t, "syscall", protoEvent.Context.Process.Thread.Syscall)
	assert.Equal(t, true, protoEvent.Context.Process.Thread.Compat)
}

func Test_convertEventWithStackaddresses(t *testing.T) {
	traceEvent := trace.Event{
		StackAddresses: []uint64{1, 2, 3},
	}

	protoEvent := convertTraceeEventToProto(traceEvent)

	expected := []*pb.StackAddress{
		{Address: 1},
		{Address: 2},
		{Address: 3},
	}

	for i := range expected {
		assert.DeepEqual(t, expected[i].Address, protoEvent.Context.Process.Thread.UserStackTrace.Addresses[i].Address)
	}
}

func Test_convertEventWithContainerContext(t *testing.T) {
	traceEvent := trace.Event{
		Container: trace.Container{
			ID:          "containerID",
			Name:        "containerName",
			ImageName:   "imageName",
			ImageDigest: "imageDigest",
		},
	}

	protoEvent := convertTraceeEventToProto(traceEvent)

	assert.Equal(t, "containerID", protoEvent.Context.Container.Id)
	assert.Equal(t, "containerName", protoEvent.Context.Container.Name)
	assert.Equal(t, "imageName", protoEvent.Context.Container.Image.Name)
	assert.DeepEqual(t, []string{"imageDigest"}, protoEvent.Context.Container.Image.RepoDigests)
}

func Test_convertEventWithK8sContext(t *testing.T) {
	traceEvent := trace.Event{
		Kubernetes: trace.Kubernetes{
			PodName:      "podName",
			PodNamespace: "podNamespace",
			PodUID:       "podUID",
		},
	}

	protoEvent := convertTraceeEventToProto(traceEvent)

	assert.Equal(t, "podName", protoEvent.Context.K8S.Pod.Name)
	assert.Equal(t, "podNamespace", protoEvent.Context.K8S.Namespace.Name)
	assert.Equal(t, "podUID", protoEvent.Context.K8S.Pod.Uid)
}

func Test_convertEventWithThreat(t *testing.T) {
	traceEvent := trace.Event{
		Metadata: &trace.Metadata{
			Description: "An attempt to abuse the Docker UNIX ..",
			Properties: map[string]interface{}{
				"Severity":    2,
				"Category":    "privilege-escalation",
				"Technique":   "Exploitation for Privilege Escalation",
				"id":          "attack-pattern--b21c3b2d",
				"external_id": "T1068",
			},
		},
	}

	protoEvent := convertTraceeEventToProto(traceEvent)

	assert.Equal(t, "An attempt to abuse the Docker UNIX ..", protoEvent.Threat.Description)
	assert.Equal(t, "privilege-escalation", protoEvent.Threat.MitreTactic.Name)
	assert.Equal(t, "Exploitation for Privilege Escalation", protoEvent.Threat.MitreTechnique.Name)
	assert.Equal(t, "attack-pattern--b21c3b2d", protoEvent.Threat.MitreTechnique.Id)
	assert.Equal(t, "T1068", protoEvent.Threat.MitreTechnique.ExternalId)
}

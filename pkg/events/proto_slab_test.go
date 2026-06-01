package events

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestEventSlabReset(t *testing.T) {
	t.Parallel()

	s := &eventSlab{}
	s.event.Id = 42
	s.event.Name = "dirty"
	s.policies.Matched = []string{"a", "b"}
	s.dataValues[0].Name = "x"
	s.dataValues[0].Value = &pb.EventValue_Int64{Int64: 7}
	s.dataPtrs[0] = &s.dataValues[0]

	s.reset()

	assert.Equal(t, pb.EventId(0), s.event.Id)
	assert.Empty(t, s.event.Name)
	assert.Empty(t, s.policies.Matched)
	for i := range s.dataValues {
		assert.Empty(t, s.dataValues[i].Name, "dataValues[%d].Name not reset", i)
		assert.Nil(t, s.dataValues[i].Value, "dataValues[%d].Value not reset", i)
		assert.Nil(t, s.dataPtrs[i], "dataPtrs[%d] not reset", i)
	}
}

func TestProtoSlabPoolReuse(t *testing.T) {
	// Not parallel — protoSlabPool is a process-wide pool whose internal state
	// can be perturbed by other tests running concurrently.
	first, ok := protoSlabPool.Get().(*eventSlab)
	require.True(t, ok)
	first.event.Name = "marker"
	protoSlabPool.Put(first)

	// sync.Pool does not guarantee which slab is returned, but with no other
	// activity on the pool the next Get is overwhelmingly likely to return the
	// one we just Put. Either way the contract under test is that the slab is
	// usable after reset.
	second, ok := protoSlabPool.Get().(*eventSlab)
	require.True(t, ok)
	second.reset()
	assert.Empty(t, second.event.Name, "reset should have cleared event.Name")
	protoSlabPool.Put(second)
}

func TestPipelineEvent_ToProto_AttachesSlab(t *testing.T) {
	t.Parallel()

	pe := NewPipelineEvent(buildSyntheticTraceEvent())
	require.NotNil(t, pe)
	require.Nil(t, pe.protoSlab)

	protoEvent := pe.ToProto()
	require.NotNil(t, protoEvent)
	require.NotNil(t, pe.protoSlab, "ToProto should attach a slab")
	assert.Same(t, &pe.protoSlab.event, protoEvent, "ProtoEvent should be backed by the slab")
}

func TestPipelineEvent_Reset_ReturnsSlab(t *testing.T) {
	t.Parallel()

	pe := NewPipelineEvent(buildSyntheticTraceEvent())
	_ = pe.ToProto()
	require.NotNil(t, pe.protoSlab)

	pe.Reset()
	assert.Nil(t, pe.protoSlab, "Reset should detach the slab")
	assert.Nil(t, pe.ProtoEvent, "Reset should clear ProtoEvent")
}

func TestPipelineEvent_DetachProto(t *testing.T) {
	t.Parallel()

	pe := NewPipelineEvent(buildSyntheticTraceEvent())
	_ = pe.ToProto()
	slabBefore := pe.protoSlab
	require.NotNil(t, slabBefore)

	detached := pe.DetachProto()
	require.NotNil(t, detached)
	assert.Nil(t, pe.protoSlab, "DetachProto should clear protoSlab")
	assert.Nil(t, pe.ProtoEvent, "DetachProto should clear ProtoEvent")

	// Reset must not return the slab a second time after DetachProto.
	pe.Reset()
	// We cannot directly assert that protoSlabPool did not get a duplicate put,
	// but we can verify the field is nil and that subsequent Resets are no-ops.
	assert.Nil(t, pe.protoSlab)
}

func TestProtoArgsOverflow(t *testing.T) {
	t.Parallel()

	execveID, ok := Core.GetDefinitionIDByName("execve")
	require.True(t, ok)

	// Build an event with more args than maxSlabArgs. Use simple int args so
	// they all match a primitive case in fillEventValue.
	args := make([]trace.Argument, 0, maxSlabArgs+4)
	for i := 0; i < maxSlabArgs+4; i++ {
		args = append(args, trace.Argument{
			ArgMeta: trace.ArgMeta{Name: fmt.Sprintf("arg%d", i), Type: "int"},
			Value:   int32(i),
		})
	}

	e := &trace.Event{
		EventID:   int(execveID),
		EventName: "execve",
		ProcessID: 1234,
		Args:      args,
	}

	protoEvent := ConvertToProto(e)
	require.NotNil(t, protoEvent)
	require.Len(t, protoEvent.Data, maxSlabArgs+4)

	for i, ev := range protoEvent.Data {
		assert.Equal(t, fmt.Sprintf("arg%d", i), ev.Name)
		v, ok := ev.Value.(*pb.EventValue_Int32)
		require.True(t, ok, "arg %d had unexpected type %T", i, ev.Value)
		assert.Equal(t, int32(i), v.Int32)
	}
}

// TestProtoStableAcrossSlabReuse asserts that converting the same event twice
// (with the slab returning to the pool in between) produces equivalent proto
// output. This is the property that ensures pool reuse is safe.
func TestProtoStableAcrossSlabReuse(t *testing.T) {
	t.Parallel()

	e := buildSyntheticTraceEvent()

	first := ConvertToProto(e)
	firstClone, ok := proto.Clone(first).(*pb.Event)
	require.True(t, ok)

	// Return the first slab to the pool, then convert again. The next Get may
	// return the same slab.
	s, ok := protoSlabPool.Get().(*eventSlab)
	require.True(t, ok)
	protoSlabPool.Put(s)

	second := ConvertToProto(e)
	assert.True(t, proto.Equal(firstClone, second),
		"second conversion diverged from first.\nfirst: %v\nsecond: %v", firstClone, second)
}

// buildSyntheticTraceEvent returns a representative trace.Event with workload,
// container, kubernetes, policies and a mix of primitive args. Shared by tests
// and benchmarks.
func buildSyntheticTraceEvent() *trace.Event {
	execveID, _ := Core.GetDefinitionIDByName("execve")
	return &trace.Event{
		EventID:             int(execveID),
		EventName:           "execve",
		Timestamp:           1700000000000000000,
		ProcessID:           1234,
		ThreadID:            1234,
		HostProcessID:       1234,
		HostThreadID:        1234,
		ParentProcessID:     1,
		HostParentProcessID: 1,
		UserID:              1000,
		ProcessName:         "bash",
		HostName:            "test-host",
		ContainerID:         "abcd1234",
		Container: trace.Container{
			ID:        "abcd1234",
			Name:      "my-container",
			ImageName: "nginx:latest",
		},
		Kubernetes: trace.Kubernetes{
			PodName:      "my-pod",
			PodNamespace: "default",
			PodUID:       "uid-xyz",
		},
		ThreadEntityId:  42,
		ProcessEntityId: 42,
		ParentEntityId:  17,
		ThreadStartTime: 1699000000000000000,
		Args: []trace.Argument{
			{ArgMeta: trace.ArgMeta{Name: "pathname", Type: "string"}, Value: "/usr/bin/ls"},
			{ArgMeta: trace.ArgMeta{Name: "argv", Type: "[]string"}, Value: []string{"ls", "-la"}},
			{ArgMeta: trace.ArgMeta{Name: "envp", Type: "[]string"}, Value: []string{"HOME=/root"}},
			{ArgMeta: trace.ArgMeta{Name: "dirfd", Type: "int"}, Value: int32(-100)},
			{ArgMeta: trace.ArgMeta{Name: "flags", Type: "int"}, Value: int32(0)},
		},
		MatchedPolicies: []string{"policy1"},
	}
}

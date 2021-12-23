package process_tree

import (
	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestProcessTree_ProcessFork(t *testing.T) {
	newProcessTID := 22482
	forkEvent := external.Event{
		Timestamp:           1639044471927303690,
		ProcessID:           0,
		ThreadID:            0,
		ParentProcessID:     22422,
		HostProcessID:       22447,
		HostThreadID:        22447,
		HostParentProcessID: 22422,
		UserID:              0,
		MountNS:             4026532548,
		PIDNS:               4026532551,
		ProcessName:         "sh",
		HostName:            "aac1fa476fcd",
		ContainerID:         TestContainerID,
		EventID:             1002,
		EventName:           "sched_process_fork",
		ArgsNum:             4,
		ReturnValue:         0,
		StackAddresses:      nil,
		Args: []external.Argument{
			{ArgMeta: external.ArgMeta{Name: "parent_tid", Type: "int"}, Value: int32(22447)},
			{ArgMeta: external.ArgMeta{Name: "parent_ns_tid", Type: "int"}, Value: int32(0)},
			{ArgMeta: external.ArgMeta{Name: "parent_pid", Type: "int"}, Value: int32(22447)},
			{ArgMeta: external.ArgMeta{Name: "parent_ns_pid", Type: "int"}, Value: int32(0)},
			{ArgMeta: external.ArgMeta{Name: "child_tid", Type: "int"}, Value: int32(newProcessTID)},
			{ArgMeta: external.ArgMeta{Name: "child_ns_tid", Type: "int"}, Value: int32(0)},
			{ArgMeta: external.ArgMeta{Name: "child_pid", Type: "int"}, Value: int32(newProcessTID)},
			{ArgMeta: external.ArgMeta{Name: "child_ns_pid", Type: "int"}, Value: int32(0)},
		},
	}
	tree := ProcessTree{
		processes:  map[int]*types.ProcessInfo{},
		containers: map[string]*containerProcessTree{},
	}
	require.NoError(t, tree.processFork(forkEvent))
	_, err := tree.GetProcessInfo(newProcessTID)
	assert.NoError(t, err)
}

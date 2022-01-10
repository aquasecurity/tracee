package process_tree

import (
	"github.com/RoaringBitmap/roaring"
	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

const pid = 22482
const ppid = 22447
const shCtime = 1639044471927000000
const cpid = 3
const cppid = 2
const threadTID = pid + 1
const threadCTID = cpid + 1

func TestProcessTree_ProcessFork(t *testing.T) {
	type expectedValues struct {
		status        roaring.Bitmap
		livingThreads []int
	}
	t.Run("Main thread fork", func(t *testing.T) {
		testCases := []struct {
			testName string
			tree     ProcessTree
			expected expectedValues
		}{
			{
				testName: "Existing executed process",
				tree: generateProcessTree(&processNode{
					ProcessName: "sh",
					InHostIDs: types.ProcessIDs{
						Pid:  pid,
						Ppid: ppid,
					},
					InContainerIDs: types.ProcessIDs{
						Pid:  cpid,
						Ppid: cppid,
					},
					ExecutionBinary: types.BinaryInfo{
						Path:  "/bin/sh",
						Hash:  "",
						Ctime: shCtime,
					},
					ExecTime:    shCtime,
					ContainerID: TestContainerID,
					ThreadsExits: map[int]timestamp{
						pid: timestamp(0),
					},
					IsAlive: true,
					Status:  *roaring.BitmapOf(uint32(types.Executed), uint32(types.GeneralCreated)),
				}),
				expected: expectedValues{
					*roaring.BitmapOf(uint32(types.GeneralCreated), uint32(types.Forked), uint32(types.Executed)),
					[]int{pid},
				},
			},
			{
				testName: "Lost exit event - existing forked process",
				tree: generateProcessTree(&processNode{
					InHostIDs: types.ProcessIDs{
						Pid:  pid,
						Ppid: 10,
					},
					InContainerIDs: types.ProcessIDs{
						Pid:  pid,
						Ppid: 10,
					},
					StartTime: shCtime - 100000,
					ThreadsExits: map[int]timestamp{
						pid: timestamp(0),
					},
					IsAlive: true,
					Status:  *roaring.BitmapOf(uint32(types.Forked)),
				}),
				expected: expectedValues{
					*roaring.BitmapOf(uint32(types.Forked), uint32(types.GeneralCreated)),
					[]int{pid},
				},
			},
			{
				testName: "Lost exit event - existing completed process",
				tree: generateProcessTree(&processNode{
					ProcessName: "sleep",
					InHostIDs: types.ProcessIDs{
						Pid:  pid,
						Ppid: 10,
					},
					InContainerIDs: types.ProcessIDs{
						Pid:  pid,
						Ppid: 10,
					},
					ExecutionBinary: types.BinaryInfo{
						Path:  "/bin/busybox",
						Hash:  "",
						Ctime: shCtime - 200000,
					},
					ExecTime:    shCtime - 100000,
					StartTime:   shCtime - 100000,
					ContainerID: "",
					ThreadsExits: map[int]timestamp{
						pid: timestamp(0),
					},
					IsAlive: true,
					Status:  *roaring.BitmapOf(uint32(types.GeneralCreated), uint32(types.Forked), uint32(types.Executed)),
				}),
				expected: expectedValues{
					*roaring.BitmapOf(uint32(types.Forked), uint32(types.GeneralCreated)),
					[]int{pid},
				},
			},
			{
				testName: "Existing hollow parent process",
				tree: generateProcessTree(&processNode{
					InHostIDs: types.ProcessIDs{
						Pid: pid,
					},
					InContainerIDs: types.ProcessIDs{
						Pid: cpid,
					},
					Status: *roaring.BitmapOf(uint32(types.HollowParent)),
				}),
				expected: expectedValues{
					*roaring.BitmapOf(uint32(types.GeneralCreated), uint32(types.Forked)),
					[]int{pid},
				},
			},
			{
				testName: "Existing general event process",
				tree: generateProcessTree(&processNode{
					ProcessName: "sh",
					InHostIDs: types.ProcessIDs{
						Pid:  pid,
						Ppid: ppid,
					},
					InContainerIDs: types.ProcessIDs{
						Pid:  cpid,
						Ppid: cppid,
					},
					ContainerID: TestContainerID,
					ThreadsExits: map[int]timestamp{
						pid: timestamp(0),
					},
					IsAlive: true,
					Status:  *roaring.BitmapOf(uint32(types.GeneralCreated)),
				}),
				expected: expectedValues{
					*roaring.BitmapOf(uint32(types.GeneralCreated), uint32(types.Forked)),
					[]int{pid},
				},
			},
			{
				testName: "Non existing process",
				tree: ProcessTree{
					processes: map[int]*processNode{},
				},
				expected: expectedValues{
					*roaring.BitmapOf(uint32(types.Forked), uint32(types.GeneralCreated)),
					[]int{pid},
				},
			},
		}
		forkEvent := generateMainForkEvent()
		for _, testCase := range testCases {
			t.Run(testCase.testName, func(t *testing.T) {
				require.NoError(t, testCase.tree.processForkEvent(&forkEvent))
				p, err := testCase.tree.GetProcessInfo(pid)
				require.NoError(t, err)
				assert.Equal(t, testCase.expected.status.ToArray(), p.Status.ToArray())
				assert.Equal(t, len(testCase.expected.livingThreads), len(p.ThreadsExits))
				for _, livingTID := range testCase.expected.livingThreads {
					assert.Contains(t, p.ThreadsExits, livingTID)
					assert.Equal(t, timestamp(0), p.ThreadsExits[livingTID])
				}
				assert.Equal(t, forkEvent.HostProcessID, p.InHostIDs.Ppid)
				assert.Equal(t, forkEvent.ProcessID, p.InContainerIDs.Ppid)
			})
		}
	})

	t.Run("Normal thread fork", func(t *testing.T) {
		testCases := []struct {
			testName string
			tree     ProcessTree
			expected expectedValues
		}{
			{
				testName: "Existing executed process",
				tree: generateProcessTree(&processNode{
					ProcessName: "sh",
					InHostIDs: types.ProcessIDs{
						Pid:  pid,
						Ppid: ppid,
					},
					InContainerIDs: types.ProcessIDs{
						Pid:  cpid,
						Ppid: cppid,
					},
					ExecutionBinary: types.BinaryInfo{
						Path:  "/bin/sh",
						Hash:  "",
						Ctime: shCtime,
					},
					ExecTime:    shCtime,
					ContainerID: TestContainerID,
					ThreadsExits: map[int]timestamp{
						pid: timestamp(0),
					},
					IsAlive: true,
					Status:  *roaring.BitmapOf(uint32(types.GeneralCreated), uint32(types.Executed)),
				}),
				expected: expectedValues{
					*roaring.BitmapOf(uint32(types.GeneralCreated), uint32(types.Executed)),
					[]int{pid, threadTID},
				},
			},
			{
				testName: "Existing forked process",
				tree: generateProcessTree(&processNode{
					InHostIDs: types.ProcessIDs{
						Pid:  pid,
						Ppid: ppid,
					},
					InContainerIDs: types.ProcessIDs{
						Pid:  cpid,
						Ppid: cppid,
					},
					StartTime:   shCtime,
					ProcessName: "sh",
					ThreadsExits: map[int]timestamp{
						pid: timestamp(0),
					},
					IsAlive: true,
					Status:  *roaring.BitmapOf(uint32(types.GeneralCreated), uint32(types.Forked)),
				}),
				expected: expectedValues{
					*roaring.BitmapOf(uint32(types.GeneralCreated), uint32(types.Forked)),
					[]int{pid, threadTID},
				},
			},
			{
				testName: "Existing completed process",
				tree: generateProcessTree(&processNode{
					ProcessName: "sh",
					InHostIDs: types.ProcessIDs{
						Pid:  pid,
						Ppid: ppid,
					},
					InContainerIDs: types.ProcessIDs{
						Pid:  cpid,
						Ppid: cppid,
					},
					ExecutionBinary: types.BinaryInfo{
						Path:  "/bin/sh",
						Hash:  "",
						Ctime: shCtime,
					},
					ExecTime:    shCtime,
					StartTime:   shCtime,
					ContainerID: TestContainerID,
					ThreadsExits: map[int]timestamp{
						pid: timestamp(0),
					},
					IsAlive: true,
					Status:  *roaring.BitmapOf(uint32(types.GeneralCreated), uint32(types.Forked), uint32(types.Executed)),
				}),
				expected: expectedValues{
					*roaring.BitmapOf(uint32(types.GeneralCreated), uint32(types.Forked), uint32(types.Executed)),
					[]int{pid, threadTID},
				},
			},
			{
				testName: "Existing hollow parent process",
				tree: generateProcessTree(&processNode{
					InHostIDs: types.ProcessIDs{
						Pid: pid,
					},
					InContainerIDs: types.ProcessIDs{
						Pid: cpid,
					},
					Status:       *roaring.BitmapOf(uint32(types.HollowParent)),
					ThreadsExits: map[int]timestamp{},
				}),
				expected: expectedValues{
					*roaring.BitmapOf(uint32(types.GeneralCreated)),
					[]int{pid, threadTID},
				},
			},
			{
				testName: "Existing general event process",
				tree: generateProcessTree(&processNode{
					ProcessName: "sh",
					InHostIDs: types.ProcessIDs{
						Pid:  pid,
						Ppid: ppid,
					},
					InContainerIDs: types.ProcessIDs{
						Pid:  cpid,
						Ppid: cppid,
					},
					ContainerID: TestContainerID,
					ThreadsExits: map[int]timestamp{
						pid: timestamp(0),
					},
					IsAlive: true,
					Status:  *roaring.BitmapOf(uint32(types.GeneralCreated)),
				}),
				expected: expectedValues{
					*roaring.BitmapOf(uint32(types.GeneralCreated)),
					[]int{pid, threadTID},
				},
			},
			{
				testName: "Non existing process",
				tree: ProcessTree{
					processes: map[int]*processNode{},
				},
				expected: expectedValues{
					*roaring.BitmapOf(uint32(types.GeneralCreated)),
					[]int{pid, threadTID},
				},
			},
		}
		for _, testCase := range testCases {
			t.Run(testCase.testName, func(t *testing.T) {
				forkEvent := generateThreadForkEvent()
				require.NoError(t, testCase.tree.processForkEvent(&forkEvent))
				p, err := testCase.tree.GetProcessInfo(pid)
				require.NoError(t, err)
				assert.Equal(t, testCase.expected.status.ToArray(), p.Status.ToArray())
				assert.Equal(t, len(testCase.expected.livingThreads), len(p.ThreadsExits))
				for _, livingTID := range testCase.expected.livingThreads {
					assert.Contains(t, p.ThreadsExits, livingTID)
					assert.Equal(t, timestamp(0), p.ThreadsExits[livingTID])
				}
				assert.Equal(t, forkEvent.ProcessName, p.ProcessName)
				assert.Equal(t, forkEvent.HostProcessID, p.InHostIDs.Pid)
				assert.Equal(t, forkEvent.HostParentProcessID, p.InHostIDs.Ppid)
				assert.Equal(t, forkEvent.ProcessID, p.InContainerIDs.Pid)
				assert.Equal(t, forkEvent.ParentProcessID, p.InContainerIDs.Ppid)
			})
		}
	})

}

func generateProcessTree(p *processNode) ProcessTree {
	return ProcessTree{
		processes: map[int]*processNode{
			p.InHostIDs.Pid: p,
		},
	}
}

func generateMainForkEvent() external.Event {
	return external.Event{
		Timestamp:           1639044471927303690,
		ProcessID:           cppid,
		ThreadID:            cppid,
		ParentProcessID:     1,
		HostProcessID:       ppid,
		HostThreadID:        ppid,
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
			{ArgMeta: external.ArgMeta{Name: "parent_tid", Type: "int"}, Value: int32(ppid)},
			{ArgMeta: external.ArgMeta{Name: "parent_ns_tid", Type: "int"}, Value: int32(cppid)},
			{ArgMeta: external.ArgMeta{Name: "parent_pid", Type: "int"}, Value: int32(ppid)},
			{ArgMeta: external.ArgMeta{Name: "parent_ns_pid", Type: "int"}, Value: int32(cppid)},
			{ArgMeta: external.ArgMeta{Name: "child_tid", Type: "int"}, Value: int32(pid)},
			{ArgMeta: external.ArgMeta{Name: "child_ns_tid", Type: "int"}, Value: int32(cpid)},
			{ArgMeta: external.ArgMeta{Name: "child_pid", Type: "int"}, Value: int32(pid)},
			{ArgMeta: external.ArgMeta{Name: "child_ns_pid", Type: "int"}, Value: int32(cpid)},
		},
	}
}

func generateThreadForkEvent() external.Event {
	return external.Event{
		Timestamp:           1639044471927303690,
		ProcessID:           cpid,
		ThreadID:            cpid,
		ParentProcessID:     cppid,
		HostProcessID:       pid,
		HostThreadID:        pid,
		HostParentProcessID: ppid,
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
			{ArgMeta: external.ArgMeta{Name: "parent_tid", Type: "int"}, Value: int32(pid)},
			{ArgMeta: external.ArgMeta{Name: "parent_ns_tid", Type: "int"}, Value: int32(cpid)},
			{ArgMeta: external.ArgMeta{Name: "parent_pid", Type: "int"}, Value: int32(pid)},
			{ArgMeta: external.ArgMeta{Name: "parent_ns_pid", Type: "int"}, Value: int32(cpid)},
			{ArgMeta: external.ArgMeta{Name: "child_tid", Type: "int"}, Value: int32(threadTID)},
			{ArgMeta: external.ArgMeta{Name: "child_ns_tid", Type: "int"}, Value: int32(threadCTID)},
			{ArgMeta: external.ArgMeta{Name: "child_pid", Type: "int"}, Value: int32(pid)},
			{ArgMeta: external.ArgMeta{Name: "child_ns_pid", Type: "int"}, Value: int32(cpid)},
		},
	}
}

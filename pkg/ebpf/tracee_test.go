package ebpf

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events"
)

func Test_getTailCalls(t *testing.T) {
	testCases := []struct {
		name              string
		events            map[events.ID]eventConfig
		expectedTailCalls []events.TailCall
		expectedErr       error
	}{
		{
			name: "happy path - some direct syscalls and syscall requiring events",
			events: map[events.ID]eventConfig{
				events.Ptrace:           {submit: ^uint64(0), emit: ^uint64(0)},
				events.ClockSettime:     {submit: ^uint64(0), emit: ^uint64(0)},
				events.SecurityFileOpen: {submit: ^uint64(0), emit: ^uint64(0)},
				events.MemProtAlert:     {submit: ^uint64(0), emit: ^uint64(0)},
				events.SocketDup:        {submit: ^uint64(0), emit: ^uint64(0)},
			},
			expectedTailCalls: []events.TailCall{
				{MapName: "sys_exit_tails", MapIndexes: []uint32{uint32(events.Dup), uint32(events.Dup2), uint32(events.Dup3)}, ProgName: "sys_dup_exit_tail"},
				{MapName: "sys_enter_init_tail", MapIndexes: []uint32{uint32(events.Dup), uint32(events.Dup2), uint32(events.Dup3)}, ProgName: "sys_enter_init"},
				{MapName: "sys_exit_init_tail", MapIndexes: []uint32{uint32(events.Dup), uint32(events.Dup2), uint32(events.Dup3)}, ProgName: "sys_exit_init"},
				{MapName: "sys_enter_init_tail", MapIndexes: []uint32{
					uint32(events.Open), uint32(events.Openat), uint32(events.Openat2), uint32(events.OpenByHandleAt),
					uint32(events.Execve), uint32(events.Execveat),
				}, ProgName: "sys_enter_init"},
				{MapName: "sys_enter_init_tail", MapIndexes: []uint32{uint32(events.Mmap), uint32(events.Mprotect), uint32(events.PkeyMprotect)}, ProgName: "sys_enter_init"},
				{MapName: "sys_enter_init_tail", MapIndexes: []uint32{uint32(events.Ptrace), uint32(events.ClockSettime)}, ProgName: "sys_enter_init"},
				{MapName: "sys_enter_submit_tail", MapIndexes: []uint32{uint32(events.Ptrace), uint32(events.ClockSettime)}, ProgName: "sys_enter_submit"},
				{MapName: "sys_exit_init_tail", MapIndexes: []uint32{uint32(events.Ptrace), uint32(events.ClockSettime)}, ProgName: "sys_exit_init"},
				{MapName: "sys_exit_submit_tail", MapIndexes: []uint32{uint32(events.Ptrace), uint32(events.ClockSettime)}, ProgName: "sys_exit_submit"},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tailCalls, err := getTailCalls(tc.events)
			if tc.expectedErr != nil {
				assert.ErrorIs(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
				for n := range tailCalls {
					sort.Slice(tailCalls[n].MapIndexes, func(i, j int) bool {
						return tailCalls[n].MapIndexes[i] < tailCalls[n].MapIndexes[j]
					})
				}
				for n := range tc.expectedTailCalls {
					sort.Slice(tc.expectedTailCalls[n].MapIndexes, func(i, j int) bool {
						return tc.expectedTailCalls[n].MapIndexes[i] < tc.expectedTailCalls[n].MapIndexes[j]
					})
				}
				assert.ElementsMatch(t, tailCalls, tc.expectedTailCalls)
			}
		})
	}
}

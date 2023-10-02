package main

import (
	"os"
	"runtime"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/tests/testutils"
)

// Test_callsys tests the callsys function
func Test_callsys(t *testing.T) {
	t.Parallel()

	// SYS_READ and SYS_CLOSE are syscalls that, considering this environment,
	// should not return an error when called with zeroed arguments
	syscalls := []events.ID{events.Read, events.Close}
	errs := callsys(syscalls)
	for _, err := range errs {
		assert.Equal(t, syscall.Errno(0), err)
	}

	// SYS_WRITE is a syscall that, considering this environment,
	// should return an error when called with zeroed arguments
	syscalls = []events.ID{events.Write}
	err := callsys(syscalls)[0]
	assert.Equal(t, syscall.Errno(9), err)
}

// Test_changeOwnComm tests the changeOwnComm function
func Test_changeOwnComm(t *testing.T) {
	t.Parallel()

	testutils.PinProccessToCPU()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	pid, _, _ := syscall.RawSyscall(syscall.SYS_FORK, 0, 0, 0)
	if pid == 0 { // child
		newComm := "test-comm"
		// test changing the comm to a valid string
		err := changeOwnComm(newComm)
		require.NoError(t, err, "Unexpected error")

		// double check that the comm was changed
		curComm, err := os.ReadFile("/proc/self/comm")
		require.NoError(t, err, "Readfile failed")

		curComm = curComm[:len(curComm)-1] // remove the trailing newline
		assert.Equal(t, newComm, string(curComm), "comm was not changed")

		syscall.Exit(0)
	}

	// parent
	assert.NotEqual(t, -1, pid, "Fork failed")

	_, err := syscall.Wait4(int(pid), nil, 0, nil)
	assert.NoError(t, err, "Wait4 failed")
}

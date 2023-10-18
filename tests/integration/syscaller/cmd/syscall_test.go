package main

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events"
)

var newComm = "test-comm"

func init() {
	runtime.GOMAXPROCS(1) // force tests to run in a single thread

	// This is to make sure that all threads will have the comm changed to the
	// expected value. It's indeed a hack, but it's the best that can be done to
	// have an unit test for changeOwnComm.
	err := changeOwnComm(newComm)
	if err != nil {
		panic(fmt.Sprintf("Failed to change comm: %v", err))
	}
}

// Test_callsys tests the callsys function.
func Test_callsys(t *testing.T) {
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
	assert.Equal(t, syscall.EBADF, err)
}

// Test_changeOwnComm tests the changeOwnComm function results.
// changeOwnComm is run in init() so all tests will run with the comm changed.
func Test_changeOwnComm(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	curComm, err := os.ReadFile("/proc/self/comm")
	require.NoError(t, err, "Failed to read comm")

	curComm = curComm[:len(curComm)-1] // remove the trailing newline
	assert.Equal(t, newComm, string(curComm), "Comm was not changed to the expected value")
}

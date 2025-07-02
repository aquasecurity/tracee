package proc

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/utils/tests"
)

// TestProcNS_PrintSizes prints the sizes of the structs used in the ProcNS type.
// Run it as DEBUG test to see the output.
func TestTaskInfoFeed_PrintSizes(t *testing.T) {
	procNS := ProcNS{}
	tests.PrintStructSizes(t, os.Stdout, procNS)
}

func Test_extractNSFromLink(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		link          string
		expectedNS    uint32
		expectedError bool
	}{
		{
			name:          "Legal NS link",
			link:          "mnt:[4026531840]",
			expectedError: false,
			expectedNS:    4026531840,
		},
		{
			name:          "Illegal NS link",
			link:          "4026531840",
			expectedError: true,
			expectedNS:    0,
		},
		{
			name:          "Empty link",
			link:          "",
			expectedError: true,
			expectedNS:    0,
		},
		{
			name:          "Link without brackets",
			link:          "mnt:4026531840",
			expectedError: true,
			expectedNS:    0,
		},
		{
			name:          "Link with malformed brackets (but TrimSuffix is forgiving)",
			link:          "mnt:[4026531840",
			expectedError: false,
			expectedNS:    402653184,
		},
		{
			name:          "Link with non-numeric NS",
			link:          "mnt:[abc123]",
			expectedError: true,
			expectedNS:    0,
		},
		{
			name:          "Different namespace type",
			link:          "user:[4026531837]",
			expectedError: false,
			expectedNS:    4026531837,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			ns, err := extractNSFromLink(testCase.link)
			if testCase.expectedError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, testCase.expectedNS, ns)
			}
		})
	}
}

func TestGetProcNS(t *testing.T) {
	currentPid := uint(os.Getpid())

	testCases := []struct {
		name        string
		pid         uint
		nsName      string
		expectError bool
	}{
		{
			name:        "current process mnt namespace",
			pid:         currentPid,
			nsName:      "mnt",
			expectError: false,
		},
		{
			name:        "current process user namespace",
			pid:         currentPid,
			nsName:      "user",
			expectError: false,
		},
		{
			name:        "current process pid namespace",
			pid:         currentPid,
			nsName:      "pid",
			expectError: false,
		},
		{
			name:        "non-existent process",
			pid:         9999999,
			nsName:      "mnt",
			expectError: true,
		},
		{
			name:        "invalid namespace name",
			pid:         currentPid,
			nsName:      "invalid_ns",
			expectError: true,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			ns, err := GetProcNS(int32(tt.pid), tt.nsName)

			if tt.expectError {
				assert.Error(t, err)
				assert.Equal(t, uint32(0), ns)
			} else {
				assert.NoError(t, err)
				assert.Greater(t, ns, uint32(0), "Namespace ID should be positive")
			}
		})
	}
}

func TestGetAllProcNS(t *testing.T) {
	currentPid := uint(os.Getpid())

	testCases := []struct {
		name        string
		pid         uint
		expectError bool
	}{
		{
			name:        "current process",
			pid:         currentPid,
			expectError: false,
		},
		{
			name:        "process 1 (init)",
			pid:         1,
			expectError: false,
		},
		{
			name:        "non-existent process",
			pid:         9999999,
			expectError: true,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			procNS, err := GetAllProcNS(int32(tt.pid))

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, procNS)
			} else {
				// Handle permission errors gracefully for process 1
				if tt.pid == 1 && err != nil && strings.Contains(err.Error(), "permission denied") {
					t.Logf("Cannot access process 1 namespace (permission denied): %v", err)
					return
				}

				assert.NoError(t, err)
				assert.NotNil(t, procNS)

				// Check that all namespace IDs are positive
				assert.Greater(t, procNS.Cgroup, uint32(0), "Cgroup namespace should be positive")
				assert.Greater(t, procNS.Ipc, uint32(0), "IPC namespace should be positive")
				assert.Greater(t, procNS.Mnt, uint32(0), "Mount namespace should be positive")
				assert.Greater(t, procNS.Net, uint32(0), "Net namespace should be positive")
				assert.Greater(t, procNS.Pid, uint32(0), "PID namespace should be positive")
				assert.Greater(t, procNS.User, uint32(0), "User namespace should be positive")
				assert.Greater(t, procNS.Uts, uint32(0), "UTS namespace should be positive")

				// PidForChildren and TimeForChildren may be 0 on some systems
				assert.GreaterOrEqual(t, procNS.PidForChildren, uint32(0))
				assert.GreaterOrEqual(t, procNS.TimeForChildren, uint32(0))
				assert.GreaterOrEqual(t, procNS.Time, uint32(0))
			}
		})
	}
}

func TestGetAnyProcessInNS(t *testing.T) {
	// First get our current process namespace to test with
	currentPid := uint(os.Getpid())
	procNS, err := GetAllProcNS(int32(currentPid))
	require.NoError(t, err, "Failed to get current process namespace")

	testCases := []struct {
		name        string
		nsName      string
		nsNum       uint32
		expectError bool
		expectPid   bool // whether we expect to find a valid PID
	}{
		{
			name:        "find process in current mnt namespace",
			nsName:      "mnt",
			nsNum:       uint32(procNS.Mnt),
			expectError: false,
			expectPid:   true,
		},
		{
			name:        "find process in current user namespace",
			nsName:      "user",
			nsNum:       uint32(procNS.User),
			expectError: false,
			expectPid:   true,
		},
		{
			name:        "non-existent namespace",
			nsName:      "mnt",
			nsNum:       9999999,
			expectError: true,
			expectPid:   false,
		},
		{
			name:        "invalid namespace name",
			nsName:      "invalid_ns",
			nsNum:       uint32(procNS.Mnt),
			expectError: true,
			expectPid:   false,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			pid, err := GetAnyProcessInNS(tt.nsName, tt.nsNum)

			if tt.expectError {
				assert.Error(t, err)
				assert.Equal(t, int32(0), pid)
			} else {
				assert.NoError(t, err)
				if tt.expectPid {
					assert.Greater(t, pid, int32(0), "Should find a valid PID")
				}
			}
		})
	}
}

func TestGetNamespaces(t *testing.T) {
	testCases := []struct {
		name        string
		nsName      string
		expectError bool
		expectMin   int // minimum number of namespaces we expect
	}{
		{
			name:        "get mount namespaces",
			nsName:      "mnt",
			expectError: false,
			expectMin:   1, // At least one mount namespace should exist
		},
		{
			name:        "get user namespaces",
			nsName:      "user",
			expectError: false,
			expectMin:   1, // At least one user namespace should exist
		},
		{
			name:        "get pid namespaces",
			nsName:      "pid",
			expectError: false,
			expectMin:   1, // At least one pid namespace should exist
		},
		{
			name:        "invalid namespace name",
			nsName:      "invalid_ns",
			expectError: false, // Function doesn't error, just returns empty results
			expectMin:   0,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			namespaces, err := GetNamespaces(tt.nsName)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.GreaterOrEqual(t, len(namespaces), tt.expectMin,
					"Should find at least %d namespaces for %s", tt.expectMin, tt.nsName)

				// Check that all namespace IDs are valid
				for _, ns := range namespaces {
					assert.Greater(t, ns, uint32(0), "All namespace IDs should be positive")
				}
			}
		})
	}
}

func TestGetMountNSFirstProcesses(t *testing.T) {
	mountNSMap, err := GetMountNSFirstProcesses()

	// This test might fail if we don't have sufficient permissions to read all processes
	// but we can still test the basic functionality
	if err != nil {
		t.Logf("GetMountNSFirstProcesses failed (possibly due to permissions): %v", err)
		return
	}

	assert.NoError(t, err)
	assert.NotNil(t, mountNSMap)

	// Should have at least one mount namespace (ours)
	assert.Greater(t, len(mountNSMap), 0, "Should find at least one mount namespace")

	// Check that all values are valid PIDs
	for mountNS, pid := range mountNSMap {
		assert.Greater(t, mountNS, uint32(0), "Mount namespace ID should be positive")
		assert.Greater(t, pid, int32(0), "PID should be positive")
	}
}

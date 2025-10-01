package controlplane

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/common/cgroup"
	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/containers/runtime"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/proctree"
	"github.com/aquasecurity/tracee/types/trace"
)

// mockBPFModule is a mock implementation of libbpfgo.Module for testing
type mockBPFModule struct {
	*libbpfgo.Module
}

func (m *mockBPFModule) InitPerfBuf(mapName string, eventsChan chan []byte, lostChan chan uint64, pageCnt int) (*libbpfgo.PerfBuffer, error) {
	// Return a mock PerfBuffer that doesn't actually do anything
	return &libbpfgo.PerfBuffer{}, nil
}

// createTestController creates a Controller instance for testing without requiring actual BPF setup
func createTestController(t *testing.T) *Controller {
	// Create a mock cgroups
	cgroups, err := cgroup.NewCgroups("/sys/fs/cgroup", false)
	require.NoError(t, err)

	// Create a mock cgroup manager
	cgroupManager, err := containers.New(
		true, // noContainersEnrich = true to avoid complex setup
		cgroups,
		runtime.Sockets{}, // empty sockets
		"test_map",
	)
	require.NoError(t, err)

	// Create a process tree
	processTree, err := proctree.NewProcessTree(
		context.Background(),
		proctree.ProcTreeConfig{
			Source:           proctree.SourceBoth,
			ProcessCacheSize: proctree.DefaultProcessCacheSize,
			ThreadCacheSize:  proctree.DefaultThreadCacheSize,
		},
	)
	require.NoError(t, err)

	// Create a data presentor using the real implementation
	dataPresentor := bufferdecoder.NewTypeDecoder()

	// Create controller manually without using NewController to avoid BPF setup issues
	ctrl := &Controller{
		signalChan:     make(chan []byte, 100),
		lostSignalChan: make(chan uint64),
		bpfModule:      &libbpfgo.Module{},
		signalBuffer:   &libbpfgo.PerfBuffer{},
		signalPool:     nil, // Not needed for this test
		cgroupManager:  cgroupManager,
		processTree:    processTree,
		enrichDisabled: false,
		dataPresentor:  dataPresentor,
		signalHandlers: make(map[events.ID]SignalHandler),
	}

	return ctrl
}

func TestRegisterSignalHandlers(t *testing.T) {
	ctrl := createTestController(t)

	// Test that registerSignalHandlers works without error
	err := ctrl.registerSignalHandlers()
	require.NoError(t, err, "registerSignalHandlers should not return an error")

	// Test that all expected signal handlers are registered
	expectedSignals := []events.ID{
		events.SignalCgroupMkdir,
		events.SignalCgroupRmdir,
		events.SignalSchedProcessFork,
		events.SignalSchedProcessExec,
		events.SignalSchedProcessExit,
		events.SignalHeartbeat,
	}

	for _, signalID := range expectedSignals {
		handler, exists := ctrl.signalHandlers[signalID]
		assert.True(t, exists, "Signal handler for %d should be registered", signalID)
		assert.NotNil(t, handler, "Signal handler for %d should not be nil", signalID)
	}

	// Test that the correct number of handlers are registered
	assert.Equal(t, len(expectedSignals), len(ctrl.signalHandlers), "Should have exactly %d signal handlers registered", len(expectedSignals))
}

func TestRegisterSignalHandlers_HandlerExecution(t *testing.T) {
	ctrl := createTestController(t)

	// Register signal handlers
	err := ctrl.registerSignalHandlers()
	require.NoError(t, err)

	tests := []struct {
		name     string
		signalID events.ID
		args     []trace.Argument
		wantErr  bool
	}{
		// Registered signals - should work without error
		{
			name:     "SignalCgroupMkdir should work",
			signalID: events.SignalCgroupMkdir,
			args: []trace.Argument{
				{ArgMeta: trace.ArgMeta{Name: "cgroup_id"}, Value: uint64(123)},
				{ArgMeta: trace.ArgMeta{Name: "cgroup_path"}, Value: "/sys/fs/cgroup/test"},
				{ArgMeta: trace.ArgMeta{Name: "hierarchy_id"}, Value: uint32(1)},
			},
			wantErr: false,
		},
		{
			name:     "SignalCgroupRmdir should work",
			signalID: events.SignalCgroupRmdir,
			args: []trace.Argument{
				{ArgMeta: trace.ArgMeta{Name: "cgroup_id"}, Value: uint64(123)},
				{ArgMeta: trace.ArgMeta{Name: "cgroup_path"}, Value: "/sys/fs/cgroup/test"},
				{ArgMeta: trace.ArgMeta{Name: "hierarchy_id"}, Value: uint32(1)},
			},
			wantErr: false,
		},
		// Unregistered signals - should return error
		{
			name:     "Unregistered CgroupAttachTask should return error",
			signalID: events.CgroupAttachTask,
			args:     []trace.Argument{},
			wantErr:  true,
		},
		{
			name:     "Unregistered SecurityBprmCheck should return error",
			signalID: events.SecurityBprmCheck,
			args:     []trace.Argument{},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock signal
			mockSignal := &signal{
				id:   tt.signalID,
				args: tt.args,
			}

			// Test processSignal function
			err := ctrl.processSignal(mockSignal)
			if tt.wantErr {
				assert.Error(t, err, "processSignal should return error")
				assert.Contains(t, err.Error(), "no registered handler", "Error should mention no registered handler")
			} else {
				assert.NoError(t, err, "processSignal should not return error")
			}
		})
	}
}

func TestRegisterSignalHandlers_HandlerExecution_AfterRegisterSignal(t *testing.T) {
	ctrl := createTestController(t)

	// Step 1: Register default signal handlers
	err := ctrl.registerSignalHandlers()
	require.NoError(t, err)

	// Step 2: Register 2 additional custom signals via RegisterSignal
	customSignalHandlers := map[events.ID]SignalHandler{
		events.VfsWrite: func(signalID events.ID, args []trace.Argument) error {
			// Custom handler for VfsWrite - just return success
			return nil
		},
		events.VfsRead: func(signalID events.ID, args []trace.Argument) error {
			// Custom handler for VfsRead - simulate an error condition
			if len(args) == 0 {
				return errfmt.Errorf("VfsRead handler requires arguments")
			}
			return nil
		},
	}

	err = ctrl.RegisterSignal(customSignalHandlers)
	require.NoError(t, err, "Should be able to register additional signals")

	// Step 3: Test all signals (default + newly registered)
	tests := []struct {
		name     string
		signalID events.ID
		args     []trace.Argument
		wantErr  bool
	}{
		// Test default registered signals - should work
		{
			name:     "Default SignalCgroupMkdir should work",
			signalID: events.SignalCgroupMkdir,
			args: []trace.Argument{
				{ArgMeta: trace.ArgMeta{Name: "cgroup_id"}, Value: uint64(123)},
				{ArgMeta: trace.ArgMeta{Name: "cgroup_path"}, Value: "/sys/fs/cgroup/test"},
				{ArgMeta: trace.ArgMeta{Name: "hierarchy_id"}, Value: uint32(1)},
			},
			wantErr: false,
		},
		{
			name:     "Default SignalCgroupRmdir should work",
			signalID: events.SignalCgroupRmdir,
			args: []trace.Argument{
				{ArgMeta: trace.ArgMeta{Name: "cgroup_id"}, Value: uint64(123)},
				{ArgMeta: trace.ArgMeta{Name: "cgroup_path"}, Value: "/sys/fs/cgroup/test"},
				{ArgMeta: trace.ArgMeta{Name: "hierarchy_id"}, Value: uint32(1)},
			},
			wantErr: false,
		},
		// Test newly registered custom signals
		{
			name:     "Custom VfsWrite signal should work",
			signalID: events.VfsWrite,
			args: []trace.Argument{
				{ArgMeta: trace.ArgMeta{Name: "fd"}, Value: int32(1)},
				{ArgMeta: trace.ArgMeta{Name: "count"}, Value: uint64(100)},
			},
			wantErr: false,
		},
		{
			name:     "Custom VfsRead signal with args should work",
			signalID: events.VfsRead,
			args: []trace.Argument{
				{ArgMeta: trace.ArgMeta{Name: "fd"}, Value: int32(1)},
				{ArgMeta: trace.ArgMeta{Name: "count"}, Value: uint64(50)},
			},
			wantErr: false,
		},
		{
			name:     "Custom VfsRead signal without args should fail",
			signalID: events.VfsRead,
			args:     []trace.Argument{}, // No args - should trigger error
			wantErr:  true,
		},
		// Test unregistered signals - should still return error
		{
			name:     "Unregistered SecurityBprmCheck should return error",
			signalID: events.SecurityBprmCheck,
			args:     []trace.Argument{},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock signal
			mockSignal := &signal{
				id:   tt.signalID,
				args: tt.args,
			}

			// Test processSignal - this is the public interface
			err := ctrl.processSignal(mockSignal)
			if tt.wantErr {
				assert.Error(t, err, "processSignal should return error")
				if tt.signalID == events.SecurityBprmCheck {
					assert.Contains(t, err.Error(), "no registered handler", "Error should mention no registered handler")
				}
			} else {
				assert.NoError(t, err, "processSignal should not return error")
			}
		})
	}
}

func TestRegisterSignalHandlers_DuplicateRegistration(t *testing.T) {
	ctrl := createTestController(t)

	// First registration should succeed
	err := ctrl.registerSignalHandlers()
	require.NoError(t, err)

	// Second registration should fail due to duplicate handlers
	err = ctrl.registerSignalHandlers()
	assert.Error(t, err, "Second registration should fail due to duplicate handlers")
	assert.Contains(t, err.Error(), "already exists", "Error should mention that handler already exists")
}

func TestRegisterSignal_ValidatesNilHandlers(t *testing.T) {
	ctrl := createTestController(t)

	// Test that RegisterSignal validates nil handlers
	handlers := map[events.ID]SignalHandler{
		events.SignalCgroupMkdir: nil,
	}

	err := ctrl.RegisterSignal(handlers)
	assert.Error(t, err, "RegisterSignal should reject nil handlers")
	assert.Contains(t, err.Error(), "cannot be nil", "Error should mention nil handler")
}

func TestRegisterSignal_AtomicOperation(t *testing.T) {
	ctrl := createTestController(t)

	// Register a handler first
	validHandler := func(signalID events.ID, args []trace.Argument) error { return nil }
	err := ctrl.RegisterSignal(map[events.ID]SignalHandler{
		events.SignalCgroupMkdir: validHandler,
	})
	require.NoError(t, err)

	// Try to register multiple handlers where one conflicts
	handlers := map[events.ID]SignalHandler{
		events.SignalCgroupMkdir: validHandler, // This should conflict
		events.SignalCgroupRmdir: validHandler, // This is new
	}

	err = ctrl.RegisterSignal(handlers)
	assert.Error(t, err, "RegisterSignal should fail when any handler conflicts")

	// Verify that the new handler was not registered (atomic operation)
	_, exists := ctrl.signalHandlers[events.SignalCgroupRmdir]
	assert.False(t, exists, "New handler should not be registered when operation fails")

	// Verify that the original handler is still there
	_, exists = ctrl.signalHandlers[events.SignalCgroupMkdir]
	assert.True(t, exists, "Original handler should still be registered")
}

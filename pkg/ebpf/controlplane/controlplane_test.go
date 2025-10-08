package controlplane_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/pkg/ebpf/controlplane"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

// createTestController creates a Controller instance for testing without requiring actual BPF setup
func createTestController() *controlplane.Controller {
	// Create a data presentor using the real implementation
	dataPresentor := bufferdecoder.NewTypeDecoder()

	// Create controller manually without using NewController to avoid BPF setup issues
	ctrl := controlplane.NewController(
		&libbpfgo.Module{},
		nil,
		false,
		nil,
		dataPresentor,
	)

	return ctrl
}

func TestControlPlane_SignalHandlerExecution(t *testing.T) {
	// Step 1: Build controller
	ctrl := createTestController()

	// Step 2: Register 2 additional custom signals via RegisterSignal
	customSignalHandlers := map[events.ID]controlplane.SignalHandler{
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

	err := ctrl.RegisterSignal(customSignalHandlers)
	require.NoError(t, err, "Should be able to register additional signals")

	// Step 3: Test all signals (default + newly registered)
	tests := []struct {
		name     string
		signalID events.ID
		args     []trace.Argument
		wantErr  bool
	}{
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
			mockSignal := &controlplane.Signal{
				ID:   tt.signalID,
				Data: tt.args,
			}

			// Test processSignal - this is the public interface
			err := ctrl.ProcessSignal(mockSignal)
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

func TestControlPlane_DuplicateRegistration(t *testing.T) {
	ctrl := createTestController()

	// First registration should succeed
	customSignalHandlers := map[events.ID]controlplane.SignalHandler{
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

	err := ctrl.RegisterSignal(customSignalHandlers)
	require.NoError(t, err, "Should be able to register additional signals")

	// Second registration should fail due to duplicate handlers
	err = ctrl.RegisterSignal(customSignalHandlers)
	assert.Error(t, err, "Second registration should fail due to duplicate handlers")
	assert.Contains(t, err.Error(), "already exists", "Error should mention that handler already exists")
}

func TestControlPlane_ValidatesNilHandlersRegistration(t *testing.T) {
	ctrl := createTestController()

	// Test that RegisterSignal validates nil handlers
	handlers := map[events.ID]controlplane.SignalHandler{
		events.SignalCgroupMkdir: nil,
	}

	err := ctrl.RegisterSignal(handlers)
	assert.Error(t, err, "RegisterSignal should reject nil handlers")
	assert.Contains(t, err.Error(), "cannot be nil", "Error should mention nil handler")
}

func TestControlPlane_AtomicOperationRegistration(t *testing.T) {
	ctrl := createTestController()

	// Register a handler first
	validHandler := func(signalID events.ID, args []trace.Argument) error { return nil }
	err := ctrl.RegisterSignal(map[events.ID]controlplane.SignalHandler{
		events.SignalCgroupMkdir: validHandler,
	})
	require.NoError(t, err)

	// Try to register multiple handlers where one conflicts
	handlers := map[events.ID]controlplane.SignalHandler{
		events.SignalCgroupMkdir: validHandler, // This should conflict
		events.SignalCgroupRmdir: validHandler, // This is new
	}

	err = ctrl.RegisterSignal(handlers)
	assert.Error(t, err, "RegisterSignal should fail when any handler conflicts")

	// Verify that the new handler was not registered (atomic operation)
	exists := ctrl.HasSignalHandler(events.SignalCgroupRmdir)
	assert.False(t, exists, "New handler should not be registered when operation fails")

	// Verify that the original handler is still there
	exists = ctrl.HasSignalHandler(events.SignalCgroupMkdir)
	assert.True(t, exists, "Original handler should still be registered")
}

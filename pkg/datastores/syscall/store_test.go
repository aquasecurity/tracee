package syscall

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
	"github.com/aquasecurity/tracee/pkg/events"
)

func TestNew(t *testing.T) {
	store := New(events.Core)
	require.NotNil(t, store, "New should return non-nil store")

	// Verify it implements the DataStore interface
	_, ok := store.(datastores.DataStore)
	assert.True(t, ok, "Store should implement DataStore interface")
}

func TestStore_Name(t *testing.T) {
	store := New(events.Core)
	assert.Equal(t, "syscall", store.Name(), "Name should be 'syscall'")
}

func TestStore_GetHealth(t *testing.T) {
	store := New(events.Core)

	health := store.GetHealth()
	require.NotNil(t, health, "GetHealth should return non-nil")
	assert.Equal(t, datastores.HealthHealthy, health.Status, "SyscallStore should always be healthy")
	assert.NotEmpty(t, health.Message, "Health message should be populated")
	assert.False(t, health.LastCheck.IsZero(), "LastCheck time should be set")
}

func TestStore_GetMetrics(t *testing.T) {
	store := New(events.Core)

	metrics := store.GetMetrics()
	require.NotNil(t, metrics, "GetMetrics should return non-nil")
	assert.False(t, metrics.LastAccess.IsZero(), "LastAccess time should be set")
	// Other metrics may be zero for this simple store
}

func TestStore_GetSyscallName_ValidSyscalls(t *testing.T) {
	store := New(events.Core)

	tests := []struct {
		name       string
		syscallID  int32
		expectName string
		expectOK   bool
	}{
		{
			name:       "read syscall",
			syscallID:  int32(events.Read),
			expectName: "read",
			expectOK:   true,
		},
		{
			name:       "write syscall",
			syscallID:  int32(events.Write),
			expectName: "write",
			expectOK:   true,
		},
		{
			name:       "open syscall",
			syscallID:  int32(events.Open),
			expectName: "open",
			expectOK:   true,
		},
		{
			name:       "close syscall",
			syscallID:  int32(events.Close),
			expectName: "close",
			expectOK:   true,
		},
		{
			name:       "execve syscall",
			syscallID:  int32(events.Execve),
			expectName: "execve",
			expectOK:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, err := store.GetSyscallName(tt.syscallID)
			if tt.expectOK {
				assert.NoError(t, err, "Should not return error for valid syscall")
				assert.Equal(t, tt.expectName, name, "Should return correct syscall name")
				assert.NotEmpty(t, name, "Syscall name should not be empty")
			} else {
				assert.ErrorIs(t, err, datastores.ErrNotFound, "Should return ErrNotFound for invalid syscall")
				assert.Empty(t, name, "Name should be empty for invalid syscall")
			}
		})
	}
}

func TestStore_GetSyscallName_InvalidIDs(t *testing.T) {
	store := New(events.Core)

	tests := []struct {
		name      string
		syscallID int32
	}{
		{
			name:      "negative ID",
			syscallID: -1,
		},
		{
			name:      "very large ID",
			syscallID: 10000,
		},
		{
			name:      "non-syscall event ID (network event)",
			syscallID: 700, // Network events start at 700
		},
		{
			name:      "non-syscall event ID (detector event)",
			syscallID: 7000, // Detector events start at 7000
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, err := store.GetSyscallName(tt.syscallID)
			assert.ErrorIs(t, err, datastores.ErrNotFound, "Should return ErrNotFound for invalid syscall ID")
			assert.Empty(t, name, "Name should be empty for invalid syscall ID")
		})
	}
}

func TestStore_GetSyscallID_ValidSyscalls(t *testing.T) {
	store := New(events.Core)

	tests := []struct {
		name        string
		syscallName string
		expectID    int32
		expectOK    bool
	}{
		{
			name:        "read syscall",
			syscallName: "read",
			expectID:    int32(events.Read),
			expectOK:    true,
		},
		{
			name:        "write syscall",
			syscallName: "write",
			expectID:    int32(events.Write),
			expectOK:    true,
		},
		{
			name:        "open syscall",
			syscallName: "open",
			expectID:    int32(events.Open),
			expectOK:    true,
		},
		{
			name:        "close syscall",
			syscallName: "close",
			expectID:    int32(events.Close),
			expectOK:    true,
		},
		{
			name:        "execve syscall",
			syscallName: "execve",
			expectID:    int32(events.Execve),
			expectOK:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := store.GetSyscallID(tt.syscallName)
			if tt.expectOK {
				assert.NoError(t, err, "Should not return error for valid syscall")
				assert.Equal(t, tt.expectID, id, "Should return correct syscall ID")
			} else {
				assert.ErrorIs(t, err, datastores.ErrNotFound, "Should return ErrNotFound")
				assert.Zero(t, id, "ID should be zero for invalid syscall")
			}
		})
	}
}

func TestStore_GetSyscallID_InvalidNames(t *testing.T) {
	store := New(events.Core)

	tests := []struct {
		name        string
		syscallName string
	}{
		{
			name:        "empty name",
			syscallName: "",
		},
		{
			name:        "non-existent syscall",
			syscallName: "nonexistent_syscall",
		},
		{
			name:        "non-syscall event",
			syscallName: "net_packet_ipv4", // Network event, not a syscall
		},
		{
			name:        "detector event",
			syscallName: "hooked_syscall", // Derived/detector event, not a syscall
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := store.GetSyscallID(tt.syscallName)
			assert.ErrorIs(t, err, datastores.ErrNotFound, "Should return ErrNotFound for invalid syscall name")
			assert.Zero(t, id, "ID should be zero for invalid syscall name")
		})
	}
}

func TestStore_GetSyscallName_GetSyscallID_Roundtrip(t *testing.T) {
	store := New(events.Core)

	// Test roundtrip: ID -> Name -> ID
	tests := []int32{0, 1, 2, 3, 59, 322} // Various syscall IDs

	for _, originalID := range tests {
		name, err := store.GetSyscallName(originalID)
		if err != nil {
			// Skip syscalls that don't exist on this architecture
			continue
		}

		t.Run("roundtrip_"+name, func(t *testing.T) {
			// Now convert name back to ID
			retrievedID, err := store.GetSyscallID(name)
			assert.NoError(t, err, "Should be able to convert name back to ID")
			assert.Equal(t, originalID, retrievedID, "Roundtrip should preserve ID")
		})
	}
}

func TestStore_GetSyscallID_GetSyscallName_Roundtrip(t *testing.T) {
	store := New(events.Core)

	// Test roundtrip: Name -> ID -> Name
	tests := []string{"read", "write", "open", "close", "execve", "socket"}

	for _, originalName := range tests {
		id, err := store.GetSyscallID(originalName)
		if err != nil {
			// Skip syscalls that don't exist on this architecture
			t.Logf("Skipping %s (not found on this architecture)", originalName)
			continue
		}

		t.Run("roundtrip_"+originalName, func(t *testing.T) {
			// Now convert ID back to name
			retrievedName, err := store.GetSyscallName(id)
			assert.NoError(t, err, "Should be able to convert ID back to name")
			assert.Equal(t, originalName, retrievedName, "Roundtrip should preserve name")
		})
	}
}

func TestStore_ArchitectureSpecific(t *testing.T) {
	store := New(events.Core)

	// This test verifies that the store is architecture-aware
	// The exact syscall numbers differ between x86_64 and ARM

	// Check that we can resolve at least some common syscalls
	commonSyscalls := []string{"read", "write", "open", "close"}
	foundCount := 0

	for _, name := range commonSyscalls {
		id, err := store.GetSyscallID(name)
		if err == nil {
			foundCount++
			t.Logf("Found syscall %s with ID %d", name, id)

			// Verify roundtrip works
			retrievedName, err := store.GetSyscallName(id)
			assert.NoError(t, err, "Roundtrip should work for %s", name)
			assert.Equal(t, name, retrievedName, "Roundtrip should preserve name for %s", name)
		}
	}

	assert.Greater(t, foundCount, 0, "Should find at least some common syscalls")
}

func TestStore_DataStoreInterface(t *testing.T) {
	// Verify the store properly implements the DataStore base interface
	store := New(events.Core)

	var ds datastores.DataStore = store
	assert.NotNil(t, ds, "Store should implement DataStore interface")

	assert.Equal(t, "syscall", ds.Name())
	assert.NotNil(t, ds.GetHealth())
	assert.NotNil(t, ds.GetMetrics())
}

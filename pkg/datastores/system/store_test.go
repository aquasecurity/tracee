package system

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

func TestCollectSystemInfo(t *testing.T) {
	info, err := CollectSystemInfo()
	require.NoError(t, err, "CollectSystemInfo should not return error")
	require.NotNil(t, info, "SystemInfo should not be nil")

	// Verify required fields are populated
	assert.NotEmpty(t, info.Architecture, "Architecture should be populated")
	assert.NotEmpty(t, info.KernelRelease, "KernelRelease should be populated")
	assert.NotEmpty(t, info.Hostname, "Hostname should be populated")
	assert.False(t, info.BootTime.IsZero(), "BootTime should be set")
	// TraceeVersion may be empty in test builds (it's set via ldflags at build time)

	// Verify BootTime is in the past
	assert.True(t, info.BootTime.Before(time.Now()), "BootTime should be in the past")

	// Verify init namespaces map exists (may be empty on some systems)
	assert.NotNil(t, info.InitNamespaces, "InitNamespaces map should not be nil")

	t.Logf("Collected system info: arch=%s, kernel=%s, hostname=%s, os=%s",
		info.Architecture, info.KernelRelease, info.Hostname, info.OSPrettyName)
}

func TestSystemStore_Interface(t *testing.T) {
	// Create a test SystemInfo
	testInfo := &datastores.SystemInfo{
		Architecture:    "x86_64",
		KernelRelease:   "5.15.0-test",
		Hostname:        "test-host",
		BootTime:        time.Now().Add(-time.Hour),
		TraceeStartTime: time.Now().Add(-time.Minute),
		OSName:          "Test OS",
		OSVersion:       "1.0",
		OSPrettyName:    "Test OS 1.0",
		TraceeVersion:   "v0.0.0-test",
		InitNamespaces:  map[string]uint32{"pid": 4026531836},
	}

	store := New(testInfo)
	require.NotNil(t, store, "New should return non-nil store")

	// Test DataStore interface methods
	assert.Equal(t, "system", store.Name(), "Name should be 'system'")

	health := store.GetHealth()
	require.NotNil(t, health, "GetHealth should return non-nil")
	assert.Equal(t, datastores.HealthHealthy, health.Status, "SystemStore should always be healthy")
	assert.Empty(t, health.Message, "Healthy store should have empty message")

	metrics := store.GetMetrics()
	require.NotNil(t, metrics, "GetMetrics should return non-nil")
	assert.Equal(t, int64(1), metrics.ItemCount, "ItemCount should be 1")

	// Test SystemStore-specific method
	retrievedInfo := store.GetSystemInfo()
	require.NotNil(t, retrievedInfo, "GetSystemInfo should return non-nil")
	assert.Equal(t, testInfo, retrievedInfo, "Retrieved info should match original")
	assert.Equal(t, "x86_64", retrievedInfo.Architecture)
	assert.Equal(t, "5.15.0-test", retrievedInfo.KernelRelease)
	assert.Equal(t, "test-host", retrievedInfo.Hostname)
}

func TestSystemStore_Immutability(t *testing.T) {
	// Create store with initial data
	originalInfo := &datastores.SystemInfo{
		Architecture:  "x86_64",
		KernelRelease: "5.15.0",
		Hostname:      "original",
	}

	store := New(originalInfo)

	// Get the info
	info1 := store.GetSystemInfo()
	info2 := store.GetSystemInfo()

	// Verify both calls return the same pointer (immutable reference)
	assert.Same(t, info1, info2, "GetSystemInfo should return the same reference")
	assert.Same(t, originalInfo, info1, "Should return original info pointer")
}

func TestFetchInitNamespaces(t *testing.T) {
	namespaces := fetchInitNamespaces()
	assert.NotNil(t, namespaces, "fetchInitNamespaces should return non-nil map")

	// On a standard Linux system, we should have at least some namespaces
	// But this may vary, so we just check the map is not nil
	// If we have namespaces, verify they're valid uint32 values
	for name, ns := range namespaces {
		assert.NotEmpty(t, name, "Namespace name should not be empty")
		assert.NotZero(t, ns, "Namespace value should not be zero")
		t.Logf("Found namespace: %s = %d", name, ns)
	}
}

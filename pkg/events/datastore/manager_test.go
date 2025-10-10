package datastore

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/pkg/events"
)

// mockDataStore is a thread-safe DataStore implementation for testing
// Uses a map to simulate real datastore behavior with proper lifecycle management
type mockDataStore struct {
	id   DataStoreID
	name string
	mu   sync.RWMutex      // protects data access
	data map[string]string // nil when not initialized
}

func newMockDataStore(id DataStoreID, name string) *mockDataStore {
	return &mockDataStore{
		id:   id,
		name: name,
		data: nil, // Not initialized yet
	}
}

// DataStore interface methods

func (m *mockDataStore) Initialize() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Idempotent - no-op if already initialized
	if m.data != nil {
		return nil
	}

	m.data = make(map[string]string)

	return nil
}

func (m *mockDataStore) Reset() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Idempotent - no-op if not initialized
	if m.data == nil {
		return nil
	}

	// Clear all data but keep the map allocated
	for k := range m.data {
		delete(m.data, k)
	}

	return nil
}

func (m *mockDataStore) Shutdown() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Idempotent - no-op if not initialized
	if m.data == nil {
		return nil
	}

	m.data = nil // Deallocate

	return nil
}

func (m *mockDataStore) ID() DataStoreID {
	return m.id
}

func (m *mockDataStore) Name() string {
	return m.name
}

func (m *mockDataStore) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.data == nil {
		return 0
	}

	return len(m.data)
}

// Test-specific helper methods

func (m *mockDataStore) Set(key, value string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.data != nil {
		m.data[key] = value
	}
}

func (m *mockDataStore) Get(key string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.data == nil {
		return "", false
	}

	val, ok := m.data[key]

	return val, ok
}

// isInitialized checks initialization state (test helper, not part of DataStore interface)
func (m *mockDataStore) isInitialized() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.data != nil
}

func TestDataStoreManagerBasicLifecycle(t *testing.T) {
	t.Parallel()

	dsm := NewDataStoreManager()
	const storeID DataStoreID = 1000

	// Register store
	err := dsm.RegisterDataStore(newMockDataStore(storeID, "test_datastore"))
	assert.NoError(t, err, "Failed to register datastore '%d'", storeID)

	// Claim store (should initialize)
	eventID := events.HookedSyscall
	err = dsm.ClaimDataStore(storeID, eventID)
	assert.NoError(t, err, "Failed to claim datastore '%d'", storeID)

	// Get store from manager
	ds, err := dsm.GetDataStore(storeID)
	assert.NoError(t, err, "Failed to get datastore '%d'", storeID)

	// Cast to mockDataStore (this is what users will do)
	mockStore, ok := ds.(*mockDataStore)
	assert.True(t, ok, "Expected datastore '%d' to be a mockDataStore", storeID)

	// Store should be initialized (test helper - not part of interface)
	assert.True(t, mockStore.isInitialized(), "Store '%s' should be initialized after claim", mockStore.Name())

	key1 := "key1"
	value1 := "value1"

	// Test that data structure works
	mockStore.Set(key1, value1)
	val, ok := mockStore.Get(key1)
	assert.True(t, ok, "Expected to get '%s', got '%s' (ok=%v)", value1, val, ok)
	assert.Equal(t, value1, val, "Expected to get '%s', got '%s' (ok=%v)", value1, val, ok)

	storeLen := mockStore.Len()
	assert.Equal(t, 1, storeLen, "Expected len=1, got %d", storeLen)

	// Verify claim count
	status, err := dsm.GetDataStoreStatus(storeID)
	assert.NoError(t, err, "Failed to get datastore status of '%d'", storeID)
	claimedByLen := len(status.ClaimedBy)
	assert.Equal(t, 1, claimedByLen, "Expected claimCount=1, got %d", claimedByLen)
	claimedBy := status.ClaimedBy[0]
	assert.Equal(t, eventID, claimedBy, "Expected the claiming event '%v', got '%v'", eventID, claimedBy)

	// Unclaim store
	err = dsm.UnclaimDataStore(storeID, eventID)
	assert.NoError(t, err, "Failed to unclaim datastore '%d'", storeID)

	// Store should still be initialized (test helper)
	assert.True(t, mockStore.isInitialized(), "Store '%s' should still be initialized after unclaim", mockStore.Name())

	// Data should still be there
	val, ok = mockStore.Get(key1)
	assert.True(t, ok, "Expected to find '%s' key in store '%s'", key1, mockStore.Name())
	assert.Equal(t, value1, val, "Expected '%s' for '%s' key in store '%s'", value1, key1, mockStore.Name())

	// Verify claim count is 0
	status, err = dsm.GetDataStoreStatus(storeID)
	assert.NoError(t, err, "Failed to get datastore status of '%d'", storeID)
	assert.Equal(t, 0, len(status.ClaimedBy), "Expected no claims after unclaim")

	// Unregister the store (shuts it down and removes from manager)
	err = dsm.UnregisterDataStore(storeID, false)
	assert.NoError(t, err, "Failed to unregister datastore '%d'", storeID)

	// Now store should be shut down (test helper)
	assert.False(t, mockStore.isInitialized(), "Store '%s' should be shut down after unregister", mockStore.Name())
}

func TestDataStoreManagerClaimCount(t *testing.T) {
	t.Parallel()

	dsm := NewDataStoreManager()
	const storeID DataStoreID = 2000

	err := dsm.RegisterDataStore(newMockDataStore(storeID, "shared_datastore"))
	assert.NoError(t, err, "Failed to register datastore '%d'", storeID)

	// Claim by first event
	event1 := events.SymbolsLoaded
	err = dsm.ClaimDataStore(storeID, event1)
	assert.NoError(t, err, "Failed to claim datastore '%d' for event '%v'", storeID, event1)

	// Get store from manager
	ds, err := dsm.GetDataStore(storeID)
	assert.NoError(t, err, "Failed to get datastore '%d'", storeID)

	// Cast to mockDataStore
	mockStore, ok := ds.(*mockDataStore)
	assert.True(t, ok, "Expected datastore '%d' to be a mockDataStore", storeID)

	// Store initialized once (test helper)
	assert.True(t, mockStore.isInitialized(), "Store '%s' should be initialized after first claim", mockStore.Name())

	// Add some data
	key1 := "event1_data"
	value1 := "value1"
	mockStore.Set(key1, value1)

	// Claim by second event
	event2 := events.SymbolsCollision
	err = dsm.ClaimDataStore(storeID, event2)
	assert.NoError(t, err, "Failed to claim datastore '%d' for event '%v'", storeID, event2)

	// Store should still have the same data (not re-initialized)
	val, ok := mockStore.Get(key1)
	assert.True(t, ok, "Expected to find '%s' key in store '%s'", key1, mockStore.Name())
	assert.Equal(t, value1, val, "Store data should persist across multiple claims")

	// Verify claim count is 2
	status, err := dsm.GetDataStoreStatus(storeID)
	assert.NoError(t, err, "Failed to get datastore status of '%d'", storeID)
	assert.Equal(t, 2, len(status.ClaimedBy), "Expected 2 claims")

	// Unclaim first event
	err = dsm.UnclaimDataStore(storeID, event1)
	assert.NoError(t, err, "Failed to unclaim datastore '%d' for event '%v'", storeID, event1)

	// Store should still be initialized (still has claims) - test helper
	assert.True(t, mockStore.isInitialized(), "Store '%s' should still be initialized after first unclaim", mockStore.Name())

	// Verify claim count is 1
	status, err = dsm.GetDataStoreStatus(storeID)
	assert.NoError(t, err, "Failed to get datastore status of '%d'", storeID)
	assert.Equal(t, 1, len(status.ClaimedBy), "Expected 1 claim after first unclaim")

	// Unclaim second event
	err = dsm.UnclaimDataStore(storeID, event2)
	assert.NoError(t, err, "Failed to unclaim datastore '%d' for event '%v'", storeID, event2)

	// Store should still be initialized (unclaim doesn't shutdown) - test helper
	assert.True(t, mockStore.isInitialized(), "Store '%s' should still be initialized after all unclaims", mockStore.Name())

	// Verify claim count is 0
	status, err = dsm.GetDataStoreStatus(storeID)
	assert.NoError(t, err, "Failed to get datastore status of '%d'", storeID)
	assert.Equal(t, 0, len(status.ClaimedBy), "Expected no claims after all unclaims")

	// Unregister the store
	err = dsm.UnregisterDataStore(storeID, false)
	assert.NoError(t, err, "Failed to unregister datastore '%d'", storeID)

	// Store should be shut down (test helper)
	assert.False(t, mockStore.isInitialized(), "Store '%s' should be shut down after unregister", mockStore.Name())
}

func TestDataStoreManagerReset(t *testing.T) {
	t.Parallel()

	dsm := NewDataStoreManager()
	const storeID DataStoreID = 3000

	err := dsm.RegisterDataStore(newMockDataStore(storeID, "reset_test_datastore"))
	assert.NoError(t, err, "Failed to register datastore '%d'", storeID)

	// Claim store
	eventID := events.HookedSyscall
	err = dsm.ClaimDataStore(storeID, eventID)
	assert.NoError(t, err, "Failed to claim datastore '%d'", storeID)

	// Get store
	ds, err := dsm.GetDataStore(storeID)
	assert.NoError(t, err, "Failed to get datastore '%d'", storeID)

	// Cast store to mockDataStore
	mockStore, ok := ds.(*mockDataStore)
	assert.True(t, ok, "Expected datastore '%d' to be a mockDataStore", storeID)

	// Add some data
	mockStore.Set("key1", "value1")
	mockStore.Set("key2", "value2")
	assert.Equal(t, 2, mockStore.Len(), "Expected 2 items before reset in store '%s'", mockStore.Name())

	// Try to reset store while claimed (without force) - should error
	err = dsm.ResetDataStore(storeID, false)
	assert.Error(t, err, "Expected error when resetting claimed datastore '%d' without force", storeID)
	assert.True(t, errors.Is(err, ErrDataStoreClaimed), "Error should be ErrDataStoreClaimed")

	// Data should still be there (reset failed)
	assert.Equal(t, 2, mockStore.Len(), "Expected data to remain after failed reset in store '%s'", mockStore.Name())

	// Reset with force should work
	err = dsm.ResetDataStore(storeID, true)
	assert.NoError(t, err, "Failed to force reset datastore '%d'", storeID)

	// Store should still be initialized but data cleared (test helper)
	assert.True(t, mockStore.isInitialized(), "Store '%s' should still be initialized after reset", mockStore.Name())
	assert.Equal(t, 0, mockStore.Len(), "Expected empty store after reset in '%s'", mockStore.Name())

	// Unclaim the store
	err = dsm.UnclaimDataStore(storeID, eventID)
	assert.NoError(t, err, "Failed to unclaim datastore '%d'", storeID)

	// Now reset without force should work (no claims)
	mockStore.Set("key3", "value3")
	err = dsm.ResetDataStore(storeID, false)
	assert.NoError(t, err, "Failed to reset unclaimed datastore '%d'", storeID)

	// Data should be cleared
	assert.Equal(t, 0, mockStore.Len(), "Expected empty store after reset in '%s'", mockStore.Name())

	// Unregister the store
	err = dsm.UnregisterDataStore(storeID, false)
	assert.NoError(t, err, "Failed to unregister datastore '%d'", storeID)

	// Store should be shut down (test helper)
	assert.False(t, mockStore.isInitialized(), "Store '%s' should be shut down after unregister", mockStore.Name())
}

func TestDataStoreManagerCanResetUnclaimedStore(t *testing.T) {
	t.Parallel()

	dsm := NewDataStoreManager()
	const storeID DataStoreID = 4000

	err := dsm.RegisterDataStore(newMockDataStore(storeID, "unclaimed_datastore"))
	assert.NoError(t, err, "Failed to register datastore '%d'", storeID)

	// Claim, add data, then unclaim
	eventID := events.HookedSyscall
	err = dsm.ClaimDataStore(storeID, eventID)
	assert.NoError(t, err, "Failed to claim datastore '%d'", storeID)

	// Get store from manager
	ds, err := dsm.GetDataStore(storeID)
	assert.NoError(t, err, "Failed to get datastore '%d'", storeID)

	// Cast to mockDataStore
	mockStore, ok := ds.(*mockDataStore)
	assert.True(t, ok, "Expected datastore '%d' to be a mockDataStore", storeID)

	mockStore.Set("key1", "value1")
	err = dsm.UnclaimDataStore(storeID, eventID)
	assert.NoError(t, err, "Failed to unclaim datastore '%d'", storeID)

	// Store is initialized but not claimed - reset should work without force
	err = dsm.ResetDataStore(storeID, false)
	assert.NoError(t, err, "Should be able to reset unclaimed datastore '%d'", storeID)

	// Data should be cleared
	assert.Equal(t, 0, mockStore.Len(), "Expected empty store after reset in '%s'", mockStore.Name())

	// Unregister the store
	err = dsm.UnregisterDataStore(storeID, false)
	assert.NoError(t, err, "Failed to unregister datastore '%d'", storeID)

	// Store should be shut down (test helper)
	assert.False(t, mockStore.isInitialized(), "Store '%s' should be shut down after unregister", mockStore.Name())
}

func TestDataStoreManagerCannotGetUnclaimedStore(t *testing.T) {
	t.Parallel()

	dsm := NewDataStoreManager()
	const storeID DataStoreID = 5000

	err := dsm.RegisterDataStore(newMockDataStore(storeID, "unclaimed_datastore"))
	assert.NoError(t, err, "Failed to register datastore '%d'", storeID)

	// Try to get without claiming - should fail
	_, err = dsm.GetDataStore(storeID)
	assert.Error(t, err, "Expected error when getting unclaimed datastore '%d'", storeID)
	assert.True(t, errors.Is(err, ErrDataStoreNotClaimed), "Error should be ErrDataStoreNotClaimed")

	// Cleanup: unregister (can unregister without claiming since it's never initialized)
	err = dsm.UnregisterDataStore(storeID, false)
	assert.NoError(t, err, "Failed to unregister datastore '%d'", storeID)
}

func TestDataStoreManagerIdempotentClaim(t *testing.T) {
	t.Parallel()

	dsm := NewDataStoreManager()
	const storeID DataStoreID = 6000

	err := dsm.RegisterDataStore(newMockDataStore(storeID, "idempotent_claim_datastore"))
	assert.NoError(t, err, "Failed to register datastore '%d'", storeID)

	eventID := events.HookedSyscall

	// First claim - should succeed
	err = dsm.ClaimDataStore(storeID, eventID)
	assert.NoError(t, err, "Failed first claim of datastore '%d'", storeID)

	// Second claim by same event - should succeed (idempotent)
	err = dsm.ClaimDataStore(storeID, eventID)
	assert.NoError(t, err, "Expected idempotent claim to succeed for datastore '%d'", storeID)

	// Verify store is still initialized and claimed once
	status, err := dsm.GetDataStoreStatus(storeID)
	assert.NoError(t, err, "Failed to get datastore status of '%d'", storeID)
	assert.Equal(t, 1, len(status.ClaimedBy), "Expected 1 claim after idempotent claim")

	// Cleanup
	err = dsm.UnclaimDataStore(storeID, eventID)
	assert.NoError(t, err, "Failed to unclaim datastore '%d'", storeID)

	err = dsm.UnregisterDataStore(storeID, false)
	assert.NoError(t, err, "Failed to unregister datastore '%d'", storeID)
}

func TestDataStoreManagerIdempotentRelease(t *testing.T) {
	t.Parallel()

	dsm := NewDataStoreManager()
	const storeID DataStoreID = 7000

	err := dsm.RegisterDataStore(newMockDataStore(storeID, "idempotent_release_datastore"))
	assert.NoError(t, err, "Failed to register datastore '%d'", storeID)

	eventID := events.HookedSyscall

	// Unclaim without claiming - should succeed (idempotent)
	err = dsm.UnclaimDataStore(storeID, eventID)
	assert.NoError(t, err, "Expected idempotent unclaim to succeed for datastore '%d'", storeID)

	// Claim and then unclaim twice - both should succeed
	err = dsm.ClaimDataStore(storeID, eventID)
	assert.NoError(t, err, "Failed to claim datastore '%d'", storeID)

	err = dsm.UnclaimDataStore(storeID, eventID)
	assert.NoError(t, err, "First unclaim failed for datastore '%d'", storeID)

	err = dsm.UnclaimDataStore(storeID, eventID)
	assert.NoError(t, err, "Second unclaim (idempotent) failed for datastore '%d'", storeID)

	// Cleanup
	err = dsm.UnregisterDataStore(storeID, false)
	assert.NoError(t, err, "Failed to unregister datastore '%d'", storeID)
}

func TestDataStoreManagerForceShutdown(t *testing.T) {
	t.Parallel()

	dsm := NewDataStoreManager()
	const storeID DataStoreID = 7500

	err := dsm.RegisterDataStore(newMockDataStore(storeID, "force_shutdown_datastore"))
	assert.NoError(t, err, "Failed to register datastore '%d'", storeID)

	// Claim by two events
	event1 := events.HookedSyscall
	event2 := events.SymbolsLoaded
	err = dsm.ClaimDataStore(storeID, event1)
	assert.NoError(t, err, "Failed to claim datastore '%d' for event '%v'", storeID, event1)

	err = dsm.ClaimDataStore(storeID, event2)
	assert.NoError(t, err, "Failed to claim datastore '%d' for event '%v'", storeID, event2)

	// Get store from manager
	ds, err := dsm.GetDataStore(storeID)
	assert.NoError(t, err, "Failed to get datastore '%d'", storeID)

	// Cast to mockDataStore
	mockStore, ok := ds.(*mockDataStore)
	assert.True(t, ok, "Expected datastore '%d' to be a mockDataStore", storeID)

	// Add some data
	mockStore.Set("important", "data")

	// Try normal unregister with active claims - should fail
	err = dsm.UnregisterDataStore(storeID, false)
	assert.Error(t, err, "Expected error when unregistering datastore '%d' with active claims", storeID)
	assert.True(t, errors.Is(err, ErrDataStoreClaimed), "Error should be ErrDataStoreClaimed")

	// Force unregister should succeed
	err = dsm.UnregisterDataStore(storeID, true)
	assert.NoError(t, err, "Force unregister failed for datastore '%d'", storeID)

	// Store should be shut down and removed from manager (test helper)
	assert.False(t, mockStore.isInitialized(), "Store '%s' should be shut down after force unregister", mockStore.Name())

	// Store should no longer be in manager
	_, err = dsm.GetDataStoreStatus(storeID)
	assert.Error(t, err, "Expected error getting status of unregistered datastore '%d'", storeID)
	assert.True(t, errors.Is(err, ErrDataStoreNotRegistered), "Error should be ErrDataStoreNotRegistered")
}

func TestDataStoreManagerGetAllStoreStatuses(t *testing.T) {
	t.Parallel()

	dsm := NewDataStoreManager()

	const storeID1 DataStoreID = 8000
	const storeID2 DataStoreID = 8001

	err := dsm.RegisterDataStore(newMockDataStore(storeID1, "datastore1"))
	assert.NoError(t, err, "Failed to register datastore '%d'", storeID1)

	err = dsm.RegisterDataStore(newMockDataStore(storeID2, "datastore2"))
	assert.NoError(t, err, "Failed to register datastore '%d'", storeID2)

	// Claim only first store
	err = dsm.ClaimDataStore(storeID1, events.HookedSyscall)
	assert.NoError(t, err, "Failed to claim datastore '%d'", storeID1)

	// Get first store and add some data
	ds1, err := dsm.GetDataStore(storeID1)
	assert.NoError(t, err, "Failed to get datastore '%d'", storeID1)

	mockStore1, ok := ds1.(*mockDataStore)
	assert.True(t, ok, "Expected datastore '%d' to be a mockDataStore", storeID1)

	mockStore1.Set("key1", "value1")
	mockStore1.Set("key2", "value2")

	statuses := dsm.GetAllDataStoreStatuses()
	assert.Equal(t, 2, len(statuses), "Expected 2 datastore statuses")

	// Verify first store is claimed
	var status1 *DataStoreStatus
	var status2 *DataStoreStatus
	for _, s := range statuses {
		switch s.ID {
		case storeID1:
			status1 = s
			continue
		case storeID2:
			status2 = s
			continue
		}
	}

	assert.NotNil(t, status1, "Status for datastore '%d' not found", storeID1)
	assert.Equal(t, 1, len(status1.ClaimedBy), "Expected datastore '%d' to be claimed by 1 event", storeID1)
	assert.Equal(t, 0, len(status2.ClaimedBy), "Expected datastore '%d' to be unclaimed", storeID2)
	assert.Equal(t, 2, status1.Len, "Expected datastore '%s' to have 2 items", status1.Name)
	assert.Equal(t, 0, status2.Len, "Expected datastore '%s' to have 0 items", status2.Name)

	// Cleanup
	err = dsm.UnclaimDataStore(storeID1, events.HookedSyscall)
	assert.NoError(t, err, "Failed to unclaim datastore '%d'", storeID1)

	err = dsm.UnregisterDataStore(storeID1, false)
	assert.NoError(t, err, "Failed to unregister datastore '%d'", storeID1)

	err = dsm.UnregisterDataStore(storeID2, false)
	assert.NoError(t, err, "Failed to unregister datastore '%d'", storeID2)
}

func TestDataStoreManagerResetAllDataStores(t *testing.T) {
	t.Parallel()

	dsm := NewDataStoreManager()

	const storeID1 DataStoreID = 9000
	const storeID2 DataStoreID = 9001
	const storeID3 DataStoreID = 9002

	// Register three stores
	err := dsm.RegisterDataStore(newMockDataStore(storeID1, "reset_all_store1"))
	assert.NoError(t, err, "Failed to register datastore '%d'", storeID1)

	err = dsm.RegisterDataStore(newMockDataStore(storeID2, "reset_all_store2"))
	assert.NoError(t, err, "Failed to register datastore '%d'", storeID2)

	err = dsm.RegisterDataStore(newMockDataStore(storeID3, "reset_all_store3"))
	assert.NoError(t, err, "Failed to register datastore '%d'", storeID3)

	// Claim all three stores and add data
	event1 := events.HookedSyscall
	event2 := events.SymbolsLoaded

	err = dsm.ClaimDataStore(storeID1, event1)
	assert.NoError(t, err, "Failed to claim datastore '%d'", storeID1)

	err = dsm.ClaimDataStore(storeID2, event1)
	assert.NoError(t, err, "Failed to claim datastore '%d'", storeID2)

	err = dsm.ClaimDataStore(storeID3, event2)
	assert.NoError(t, err, "Failed to claim datastore '%d'", storeID3)

	// Get stores and add data
	ds1, _ := dsm.GetDataStore(storeID1)
	mockStore1, ok := ds1.(*mockDataStore)
	assert.True(t, ok, "Expected datastore '%d' to be a mockDataStore", storeID1)
	mockStore1.Set("key1", "value1")
	mockStore1.Set("key2", "value2")

	ds2, _ := dsm.GetDataStore(storeID2)
	mockStore2, ok := ds2.(*mockDataStore)
	assert.True(t, ok, "Expected datastore '%d' to be a mockDataStore", storeID2)
	mockStore2.Set("key3", "value3")

	ds3, _ := dsm.GetDataStore(storeID3)
	mockStore3, ok := ds3.(*mockDataStore)
	assert.True(t, ok, "Expected datastore '%d' to be a mockDataStore", storeID3)
	mockStore3.Set("key4", "value4")
	mockStore3.Set("key5", "value5")

	// Verify all have data
	assert.Equal(t, 2, mockStore1.Len(), "Expected 2 items in store1")
	assert.Equal(t, 1, mockStore2.Len(), "Expected 1 item in store2")
	assert.Equal(t, 2, mockStore3.Len(), "Expected 2 items in store3")

	// Try to reset all without force - should fail because all are claimed
	err = dsm.ResetAllDataStores(false)
	assert.Error(t, err, "Expected error when resetting all claimed stores without force")

	// Data should still be there
	assert.Equal(t, 2, mockStore1.Len(), "Expected data to remain after failed reset")
	assert.Equal(t, 1, mockStore2.Len(), "Expected data to remain after failed reset")
	assert.Equal(t, 2, mockStore3.Len(), "Expected data to remain after failed reset")

	// Unclaim store1 and store2
	err = dsm.UnclaimDataStore(storeID1, event1)
	assert.NoError(t, err, "Failed to unclaim datastore '%d'", storeID1)

	err = dsm.UnclaimDataStore(storeID2, event1)
	assert.NoError(t, err, "Failed to unclaim datastore '%d'", storeID2)

	// Now reset all without force - should still fail because store3 is claimed
	err = dsm.ResetAllDataStores(false)
	assert.Error(t, err, "Expected error when some stores are still claimed")

	// Store1 and store2 should be reset, store3 should still have data
	assert.Equal(t, 0, mockStore1.Len(), "Expected store1 to be reset")
	assert.Equal(t, 0, mockStore2.Len(), "Expected store2 to be reset")
	assert.Equal(t, 2, mockStore3.Len(), "Expected store3 data to remain")

	// Add data back to store1
	mockStore1.Set("new1", "newvalue1")
	assert.Equal(t, 1, mockStore1.Len(), "Expected 1 item in store1")

	// Force reset all - should succeed
	err = dsm.ResetAllDataStores(true)
	assert.NoError(t, err, "Failed to force reset all datastores")

	// All stores should be empty now
	assert.Equal(t, 0, mockStore1.Len(), "Expected store1 to be empty after force reset")
	assert.Equal(t, 0, mockStore2.Len(), "Expected store2 to be empty after force reset")
	assert.Equal(t, 0, mockStore3.Len(), "Expected store3 to be empty after force reset")

	// All stores should still be initialized (test helper)
	assert.True(t, mockStore1.isInitialized(), "Store1 should still be initialized")
	assert.True(t, mockStore2.isInitialized(), "Store2 should still be initialized")
	assert.True(t, mockStore3.isInitialized(), "Store3 should still be initialized")

	// Cleanup
	err = dsm.UnclaimDataStore(storeID3, event2)
	assert.NoError(t, err, "Failed to unclaim datastore '%d'", storeID3)

	err = dsm.UnregisterDataStore(storeID1, false)
	assert.NoError(t, err, "Failed to unregister datastore '%d'", storeID1)

	err = dsm.UnregisterDataStore(storeID2, false)
	assert.NoError(t, err, "Failed to unregister datastore '%d'", storeID2)

	err = dsm.UnregisterDataStore(storeID3, false)
	assert.NoError(t, err, "Failed to unregister datastore '%d'", storeID3)
}

func TestDataStoreManagerUnregisterAllDataStores(t *testing.T) {
	t.Parallel()

	dsm := NewDataStoreManager()

	const storeID1 DataStoreID = 10000
	const storeID2 DataStoreID = 10001
	const storeID3 DataStoreID = 10002

	// Register three stores
	err := dsm.RegisterDataStore(newMockDataStore(storeID1, "unregister_all_store1"))
	assert.NoError(t, err, "Failed to register datastore '%d'", storeID1)

	err = dsm.RegisterDataStore(newMockDataStore(storeID2, "unregister_all_store2"))
	assert.NoError(t, err, "Failed to register datastore '%d'", storeID2)

	err = dsm.RegisterDataStore(newMockDataStore(storeID3, "unregister_all_store3"))
	assert.NoError(t, err, "Failed to register datastore '%d'", storeID3)

	// Claim all three stores
	event1 := events.HookedSyscall
	event2 := events.SymbolsLoaded

	err = dsm.ClaimDataStore(storeID1, event1)
	assert.NoError(t, err, "Failed to claim datastore '%d'", storeID1)

	err = dsm.ClaimDataStore(storeID2, event1)
	assert.NoError(t, err, "Failed to claim datastore '%d'", storeID2)

	err = dsm.ClaimDataStore(storeID3, event2)
	assert.NoError(t, err, "Failed to claim datastore '%d'", storeID3)

	// Get stores for later verification
	ds1, _ := dsm.GetDataStore(storeID1)
	mockStore1, ok := ds1.(*mockDataStore)
	assert.True(t, ok, "Expected datastore '%d' to be a mockDataStore", storeID1)

	ds2, _ := dsm.GetDataStore(storeID2)
	mockStore2, ok := ds2.(*mockDataStore)
	assert.True(t, ok, "Expected datastore '%d' to be a mockDataStore", storeID2)

	ds3, _ := dsm.GetDataStore(storeID3)
	mockStore3, ok := ds3.(*mockDataStore)
	assert.True(t, ok, "Expected datastore '%d' to be a mockDataStore", storeID3)

	// All should be initialized (test helper)
	assert.True(t, mockStore1.isInitialized(), "Store1 should be initialized")
	assert.True(t, mockStore2.isInitialized(), "Store2 should be initialized")
	assert.True(t, mockStore3.isInitialized(), "Store3 should be initialized")

	// Try to unregister all without force - should fail because all are claimed
	err = dsm.UnregisterAllDataStores(false)
	assert.Error(t, err, "Expected error when unregistering all claimed stores without force")

	// All stores should still be initialized
	assert.True(t, mockStore1.isInitialized(), "Store1 should still be initialized after failed unregister")
	assert.True(t, mockStore2.isInitialized(), "Store2 should still be initialized after failed unregister")
	assert.True(t, mockStore3.isInitialized(), "Store3 should still be initialized after failed unregister")

	// Verify stores are still registered
	statuses := dsm.GetAllDataStoreStatuses()
	assert.Equal(t, 3, len(statuses), "Expected 3 stores still registered")

	// Unclaim store1 and store2
	err = dsm.UnclaimDataStore(storeID1, event1)
	assert.NoError(t, err, "Failed to unclaim datastore '%d'", storeID1)

	err = dsm.UnclaimDataStore(storeID2, event1)
	assert.NoError(t, err, "Failed to unclaim datastore '%d'", storeID2)

	// Try again without force - should still fail because store3 is claimed
	err = dsm.UnregisterAllDataStores(false)
	assert.Error(t, err, "Expected error when some stores are still claimed")

	// Store1 and store2 should be unregistered (shut down), store3 should still be initialized
	assert.False(t, mockStore1.isInitialized(), "Store1 should be shut down")
	assert.False(t, mockStore2.isInitialized(), "Store2 should be shut down")
	assert.True(t, mockStore3.isInitialized(), "Store3 should still be initialized")

	// Only store3 should remain
	statuses = dsm.GetAllDataStoreStatuses()
	assert.Equal(t, 1, len(statuses), "Expected 1 store still registered")
	assert.Equal(t, storeID3, statuses[0].ID, "Expected store3 to remain")

	// Force unregister all - should succeed
	err = dsm.UnregisterAllDataStores(true)
	assert.NoError(t, err, "Failed to force unregister all datastores")

	// Store3 should now be shut down
	assert.False(t, mockStore3.isInitialized(), "Store3 should be shut down after force unregister")

	// No stores should remain
	statuses = dsm.GetAllDataStoreStatuses()
	assert.Equal(t, 0, len(statuses), "Expected no stores remaining after unregister all")

	// Trying to get status of any store should fail
	_, err = dsm.GetDataStoreStatus(storeID1)
	assert.Error(t, err, "Expected error getting status of unregistered store1")
	assert.True(t, errors.Is(err, ErrDataStoreNotRegistered), "Error should be ErrDataStoreNotRegistered")

	_, err = dsm.GetDataStoreStatus(storeID2)
	assert.Error(t, err, "Expected error getting status of unregistered store2")
	assert.True(t, errors.Is(err, ErrDataStoreNotRegistered), "Error should be ErrDataStoreNotRegistered")

	_, err = dsm.GetDataStoreStatus(storeID3)
	assert.Error(t, err, "Expected error getting status of unregistered store3")
	assert.True(t, errors.Is(err, ErrDataStoreNotRegistered), "Error should be ErrDataStoreNotRegistered")
}

// slowDataStore simulates slow lifecycle operations for timeout testing
type slowDataStore struct {
	id         DataStoreID
	name       string
	initDelay  time.Duration
	resetDelay time.Duration
	shutDelay  time.Duration
	mu         sync.Mutex
	data       map[string]string
}

func newSlowDataStore(id DataStoreID, name string, initDelay, resetDelay, shutDelay time.Duration) *slowDataStore {
	return &slowDataStore{
		id:         id,
		name:       name,
		initDelay:  initDelay,
		resetDelay: resetDelay,
		shutDelay:  shutDelay,
	}
}

func (s *slowDataStore) Initialize() error {
	time.Sleep(s.initDelay)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data == nil {
		s.data = make(map[string]string)
	}
	return nil
}

func (s *slowDataStore) Reset() error {
	time.Sleep(s.resetDelay)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data != nil {
		for k := range s.data {
			delete(s.data, k)
		}
	}
	return nil
}

func (s *slowDataStore) Shutdown() error {
	time.Sleep(s.shutDelay)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = nil
	return nil
}

func (s *slowDataStore) ID() DataStoreID {
	return s.id
}

func (s *slowDataStore) Name() string {
	return s.name
}

func (s *slowDataStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data == nil {
		return 0
	}
	return len(s.data)
}

func TestDataStoreManagerInitializeTimeout(t *testing.T) {
	t.Parallel()

	dsm := NewDataStoreManager(
		WithInitTimeout(100*time.Millisecond),
		WithResetTimeout(100*time.Millisecond),
		WithShutdownTimeout(100*time.Millisecond),
	)

	const storeID DataStoreID = 11000

	// Create a store that takes too long to initialize
	slowStore := newSlowDataStore(storeID, "slow_init_store", 500*time.Millisecond, 0, 0)

	err := dsm.RegisterDataStore(slowStore)
	assert.NoError(t, err, "Failed to register slow store")

	// This should timeout
	err = dsm.ClaimDataStore(storeID, events.HookedSyscall)
	assert.Error(t, err, "Expected timeout error when claiming slow store")
	assert.True(t, errors.Is(err, ErrDataStoreTimeout), "Error should be ErrDataStoreTimeout")

	// Cleanup
	err = dsm.UnregisterDataStore(storeID, true)
	assert.NoError(t, err, "Failed to force unregister store")
}

func TestDataStoreManagerResetTimeout(t *testing.T) {
	t.Parallel()

	dsm := NewDataStoreManager(
		WithInitTimeout(100*time.Millisecond),
		WithResetTimeout(100*time.Millisecond),
		WithShutdownTimeout(100*time.Millisecond),
	)

	const storeID DataStoreID = 11001

	// Create a store with slow reset
	slowStore := newSlowDataStore(storeID, "slow_reset_store", 0, 500*time.Millisecond, 0)

	err := dsm.RegisterDataStore(slowStore)
	assert.NoError(t, err, "Failed to register slow store")

	// Initialize quickly
	err = dsm.ClaimDataStore(storeID, events.HookedSyscall)
	assert.NoError(t, err, "Failed to claim store")

	err = dsm.UnclaimDataStore(storeID, events.HookedSyscall)
	assert.NoError(t, err, "Failed to unclaim store")

	// Reset should timeout
	err = dsm.ResetDataStore(storeID, false)
	assert.Error(t, err, "Expected timeout error when resetting slow store")
	assert.True(t, errors.Is(err, ErrDataStoreTimeout), "Error should be ErrDataStoreTimeout")

	// Cleanup
	err = dsm.UnregisterDataStore(storeID, true)
	assert.NoError(t, err, "Failed to force unregister store")
}

func TestDataStoreManagerShutdownTimeout(t *testing.T) {
	t.Parallel()

	dsm := NewDataStoreManager(
		WithInitTimeout(100*time.Millisecond),
		WithResetTimeout(100*time.Millisecond),
		WithShutdownTimeout(100*time.Millisecond),
	)

	const storeID DataStoreID = 11002

	// Create a store with slow shutdown
	slowStore := newSlowDataStore(storeID, "slow_shutdown_store", 0, 0, 500*time.Millisecond)

	err := dsm.RegisterDataStore(slowStore)
	assert.NoError(t, err, "Failed to register slow store")

	// Initialize quickly
	err = dsm.ClaimDataStore(storeID, events.HookedSyscall)
	assert.NoError(t, err, "Failed to claim store")

	err = dsm.UnclaimDataStore(storeID, events.HookedSyscall)
	assert.NoError(t, err, "Failed to unclaim store")

	// Unregister should timeout
	err = dsm.UnregisterDataStore(storeID, false)
	assert.Error(t, err, "Expected timeout error when unregistering slow store")
	assert.True(t, errors.Is(err, ErrDataStoreTimeout), "Error should be ErrDataStoreTimeout")
}

func TestDataStoreManagerFastOperationsNoTimeout(t *testing.T) {
	t.Parallel()

	dsm := NewDataStoreManager(
		WithInitTimeout(200*time.Millisecond),
		WithResetTimeout(200*time.Millisecond),
		WithShutdownTimeout(200*time.Millisecond),
	)

	const storeID DataStoreID = 11003

	// Create a store with fast operations
	fastStore := newSlowDataStore(storeID, "fast_store", 50*time.Millisecond, 50*time.Millisecond, 50*time.Millisecond)

	err := dsm.RegisterDataStore(fastStore)
	assert.NoError(t, err, "Failed to register fast store")

	// All operations should succeed
	err = dsm.ClaimDataStore(storeID, events.HookedSyscall)
	assert.NoError(t, err, "Claim should not timeout")

	err = dsm.UnclaimDataStore(storeID, events.HookedSyscall)
	assert.NoError(t, err, "Unclaim should not fail")

	err = dsm.ResetDataStore(storeID, false)
	assert.NoError(t, err, "Reset should not timeout")

	err = dsm.UnregisterDataStore(storeID, false)
	assert.NoError(t, err, "Unregister should not timeout")
}

// TestClaimDataStoreUnregisteredDuringInit tests the corner case where a store
// is unregistered while ClaimDataStore is calling Initialize
func TestClaimDataStoreUnregisteredDuringInit(t *testing.T) {
	t.Parallel()

	dsm := NewDataStoreManager(
		WithInitTimeout(2 * time.Second),
	)

	const storeID DataStoreID = 12000

	// Create a store with slow initialization
	slowStore := newSlowDataStore(storeID, "slow_init_unregister", 500*time.Millisecond, 0, 0)
	err := dsm.RegisterDataStore(slowStore)
	assert.NoError(t, err, "Failed to register slow store")

	var wg sync.WaitGroup
	wg.Add(2)

	var claimErr error

	// Goroutine 1: Claim (will initialize slowly)
	go func() {
		defer wg.Done()
		claimErr = dsm.ClaimDataStore(storeID, events.HookedSyscall)
	}()

	// Goroutine 2: Unregister while Initialize is running
	go func() {
		defer wg.Done()
		time.Sleep(100 * time.Millisecond) // Let Claim start and begin Initialize
		_ = dsm.UnregisterDataStore(storeID, true)
	}()

	wg.Wait()

	// The claim should fail because store was unregistered during initialization
	assert.Error(t, claimErr, "Expected error when store unregistered during initialization")
	assert.True(t, errors.Is(claimErr, ErrDataStoreUnregisteredDuringOperation),
		"Error should be ErrDataStoreUnregisteredDuringOperation")
}

// TestClaimDataStoreReRegisteredDuringInit tests the corner case where a store
// is unregistered and then re-registered with the same ID but different instance
// while ClaimDataStore is calling Initialize
func TestClaimDataStoreReRegisteredDuringInit(t *testing.T) {
	t.Parallel()

	dsm := NewDataStoreManager(
		WithInitTimeout(2 * time.Second),
	)

	const storeID DataStoreID = 12001

	// Create a store with slow initialization
	slowStore1 := newSlowDataStore(storeID, "slow_init_reregister_1", 500*time.Millisecond, 0, 0)
	err := dsm.RegisterDataStore(slowStore1)
	assert.NoError(t, err, "Failed to register first slow store")

	var wg sync.WaitGroup
	wg.Add(2)

	var claimErr error

	// Goroutine 1: Claim (will initialize slowly)
	go func() {
		defer wg.Done()
		claimErr = dsm.ClaimDataStore(storeID, events.HookedSyscall)
	}()

	// Goroutine 2: Unregister and re-register with same ID but different instance
	go func() {
		defer wg.Done()
		time.Sleep(100 * time.Millisecond) // Let Claim start and begin Initialize

		// Unregister the first store
		_ = dsm.UnregisterDataStore(storeID, true)

		// Register a NEW store with the same ID (different instance)
		slowStore2 := newSlowDataStore(storeID, "slow_init_reregister_2", 0, 0, 0)
		_ = dsm.RegisterDataStore(slowStore2)
	}()

	wg.Wait()

	// The claim should fail because store instance changed during initialization
	assert.Error(t, claimErr, "Expected error when store re-registered during initialization")
	assert.True(t, errors.Is(claimErr, ErrDataStoreReRegistered),
		"Error should be ErrDataStoreReRegistered")

	// Cleanup the second store
	_ = dsm.UnregisterDataStore(storeID, true)
}

// TestClaimDataStoreSucceedsWhenNoInterference tests that ClaimDataStore succeeds
// when no concurrent unregister happens
func TestClaimDataStoreSucceedsWhenNoInterference(t *testing.T) {
	t.Parallel()

	dsm := NewDataStoreManager(
		WithInitTimeout(2 * time.Second),
	)

	const storeID DataStoreID = 12002

	// Create a store with slow initialization
	slowStore := newSlowDataStore(storeID, "slow_init_success", 200*time.Millisecond, 0, 0)
	err := dsm.RegisterDataStore(slowStore)
	assert.NoError(t, err, "Failed to register slow store")

	// Claim should succeed even with slow initialization
	err = dsm.ClaimDataStore(storeID, events.HookedSyscall)
	assert.NoError(t, err, "Claim should succeed when no interference occurs")

	// Verify claim was added
	status, err := dsm.GetDataStoreStatus(storeID)
	assert.NoError(t, err, "Failed to get status")
	assert.Equal(t, 1, len(status.ClaimedBy), "Expected 1 claim")

	// Cleanup
	_ = dsm.UnclaimDataStore(storeID, events.HookedSyscall)
	_ = dsm.UnregisterDataStore(storeID, false)
}

// TestClaimDataStoreConcurrentClaimsSucceed tests that multiple concurrent claims
// during slow initialization all succeed (idempotent behavior)
func TestClaimDataStoreConcurrentClaimsSucceed(t *testing.T) {
	t.Parallel()

	dsm := NewDataStoreManager(
		WithInitTimeout(2 * time.Second),
	)

	const storeID DataStoreID = 12003
	const numClaimers = 10

	// Create a store with slow initialization
	slowStore := newSlowDataStore(storeID, "slow_init_concurrent", 300*time.Millisecond, 0, 0)
	err := dsm.RegisterDataStore(slowStore)
	assert.NoError(t, err, "Failed to register slow store")

	var wg sync.WaitGroup
	wg.Add(numClaimers)
	start := make(chan struct{})

	claimErrors := make([]error, numClaimers)

	// Multiple goroutines claiming concurrently
	for i := 0; i < numClaimers; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start
			claimErrors[idx] = dsm.ClaimDataStore(storeID, events.ID(13000+idx))
		}(i)
	}

	close(start)
	wg.Wait()

	// All claims should succeed
	for i, err := range claimErrors {
		assert.NoError(t, err, "Claim %d should succeed", i)
	}

	// Verify all claims were registered
	status, err := dsm.GetDataStoreStatus(storeID)
	assert.NoError(t, err, "Failed to get status")
	assert.Equal(t, numClaimers, len(status.ClaimedBy), "Expected %d claims", numClaimers)

	// Cleanup
	for i := 0; i < numClaimers; i++ {
		_ = dsm.UnclaimDataStore(storeID, events.ID(13000+i))
	}
	_ = dsm.UnregisterDataStore(storeID, false)
}

// TestUnregisterDataStoreUnregisteredDuringShutdown tests the corner case where a store
// is unregistered by another goroutine while UnregisterDataStore is calling Shutdown
func TestUnregisterDataStoreUnregisteredDuringShutdown(t *testing.T) {
	t.Parallel()

	dsm := NewDataStoreManager(
		WithShutdownTimeout(2 * time.Second),
	)

	const storeID DataStoreID = 12100

	// Create a store with slow shutdown
	slowStore := newSlowDataStore(storeID, "slow_shutdown_unregister", 0, 0, 500*time.Millisecond)
	err := dsm.RegisterDataStore(slowStore)
	assert.NoError(t, err, "Failed to register slow store")

	// Initialize it
	err = dsm.ClaimDataStore(storeID, events.HookedSyscall)
	assert.NoError(t, err, "Failed to claim store")
	err = dsm.UnclaimDataStore(storeID, events.HookedSyscall)
	assert.NoError(t, err, "Failed to unclaim store")

	var wg sync.WaitGroup
	wg.Add(2)

	var unregisterErr1, unregisterErr2 error

	// Goroutine 1: Unregister (will shutdown slowly)
	go func() {
		defer wg.Done()
		unregisterErr1 = dsm.UnregisterDataStore(storeID, false)
	}()

	// Goroutine 2: Try to unregister while Shutdown is running
	go func() {
		defer wg.Done()
		time.Sleep(100 * time.Millisecond) // Let first Unregister start
		unregisterErr2 = dsm.UnregisterDataStore(storeID, true)
	}()

	wg.Wait()

	// At least one should succeed, the other might fail
	if unregisterErr1 != nil && unregisterErr2 != nil {
		// Both failed - at least one should indicate a concurrency issue
		hasExpectedError := errors.Is(unregisterErr1, ErrDataStoreNotRegistered) ||
			errors.Is(unregisterErr1, ErrDataStoreUnregisteredDuringOperation) ||
			errors.Is(unregisterErr2, ErrDataStoreNotRegistered) ||
			errors.Is(unregisterErr2, ErrDataStoreUnregisteredDuringOperation)
		assert.True(t, hasExpectedError,
			"One error should be ErrDataStoreNotRegistered or ErrDataStoreUnregisteredDuringOperation")
	}
}

// TestUnregisterDataStoreReRegisteredDuringShutdown tests the corner case where a store
// is unregistered and then re-registered with the same ID but different instance
// while UnregisterDataStore is calling Shutdown
func TestUnregisterDataStoreReRegisteredDuringShutdown(t *testing.T) {
	t.Parallel()

	dsm := NewDataStoreManager(
		WithShutdownTimeout(2 * time.Second),
	)

	const storeID DataStoreID = 12101

	// Create a store with slow shutdown
	slowStore1 := newSlowDataStore(storeID, "slow_shutdown_reregister_1", 0, 0, 500*time.Millisecond)
	err := dsm.RegisterDataStore(slowStore1)
	assert.NoError(t, err, "Failed to register first slow store")

	// Initialize it
	err = dsm.ClaimDataStore(storeID, events.HookedSyscall)
	assert.NoError(t, err, "Failed to claim store")
	err = dsm.UnclaimDataStore(storeID, events.HookedSyscall)
	assert.NoError(t, err, "Failed to unclaim store")

	var wg sync.WaitGroup
	wg.Add(2)

	var unregisterErr error

	// Goroutine 1: Unregister (will shutdown slowly)
	go func() {
		defer wg.Done()
		unregisterErr = dsm.UnregisterDataStore(storeID, false)
	}()

	// Goroutine 2: Force unregister and re-register with same ID but different instance
	go func() {
		defer wg.Done()
		time.Sleep(100 * time.Millisecond) // Let first Unregister start Shutdown

		// Force unregister the first store
		_ = dsm.UnregisterDataStore(storeID, true)

		// Register a NEW store with the same ID (different instance)
		slowStore2 := newSlowDataStore(storeID, "slow_shutdown_reregister_2", 0, 0, 0)
		_ = dsm.RegisterDataStore(slowStore2)
	}()

	wg.Wait()

	// The first unregister might fail because the store was replaced
	// Either it succeeds (unregistered before replacement) or fails with ErrDataStoreReRegistered/NotRegistered
	if unregisterErr != nil {
		assert.True(t,
			errors.Is(unregisterErr, ErrDataStoreUnregisteredDuringOperation) ||
				errors.Is(unregisterErr, ErrDataStoreReRegistered) ||
				errors.Is(unregisterErr, ErrDataStoreNotRegistered),
			"Error should be one of the expected concurrency errors")
	}

	// Cleanup the second store if it exists
	_ = dsm.UnregisterDataStore(storeID, true)
}

// TestUnregisterAllDataStoresConcurrentModifications tests UnregisterAllDataStores
// when stores are being modified concurrently
func TestUnregisterAllDataStoresConcurrentModifications(t *testing.T) {
	t.Parallel()

	dsm := NewDataStoreManager(
		WithShutdownTimeout(2 * time.Second),
	)

	const numStores = 5
	const baseID DataStoreID = 12200

	// Register multiple stores
	for i := 0; i < numStores; i++ {
		storeID := baseID + DataStoreID(i)
		store := newSlowDataStore(storeID, fmt.Sprintf("concurrent_store_%d", i), 0, 0, 100*time.Millisecond)
		err := dsm.RegisterDataStore(store)
		assert.NoError(t, err, "Failed to register store %d", i)

		// Initialize each store
		err = dsm.ClaimDataStore(storeID, events.HookedSyscall)
		assert.NoError(t, err, "Failed to claim store %d", i)
	}

	var wg sync.WaitGroup
	wg.Add(3)

	var unregisterAllErr error

	// Goroutine 1: UnregisterAll (will shutdown slowly)
	go func() {
		defer wg.Done()
		unregisterAllErr = dsm.UnregisterAllDataStores(true)
	}()

	// Goroutine 2: Try to unclaim stores concurrently
	go func() {
		defer wg.Done()
		time.Sleep(50 * time.Millisecond)
		for i := 0; i < numStores; i++ {
			storeID := baseID + DataStoreID(i)
			_ = dsm.UnclaimDataStore(storeID, events.HookedSyscall)
			// May succeed or fail with "not registered"
		}
	}()

	// Goroutine 3: Try to register new stores concurrently
	go func() {
		defer wg.Done()
		time.Sleep(100 * time.Millisecond)
		for i := 0; i < numStores; i++ {
			storeID := baseID + DataStoreID(i)
			newStore := newMockDataStore(storeID, fmt.Sprintf("new_store_%d", i))
			_ = dsm.RegisterDataStore(newStore) // May succeed or fail with "already registered"
		}
	}()

	wg.Wait()

	// UnregisterAll may have errors due to concurrent modifications
	if unregisterAllErr != nil {
		// Verify errors are of expected types
		assert.True(t,
			errors.Is(unregisterAllErr, ErrDataStoreNotRegistered) ||
				errors.Is(unregisterAllErr, ErrDataStoreUnregisteredDuringOperation) ||
				errors.Is(unregisterAllErr, ErrDataStoreReRegistered) ||
				errors.Is(unregisterAllErr, ErrDataStoreClaimed),
			"Error should be one of the expected concurrency errors")
	}

	// Final cleanup - force unregister anything that might remain
	_ = dsm.UnregisterAllDataStores(true)
}

// TestUnregisterAllDataStoresCleanupPhaseErrors tests that UnregisterAllDataStores
// properly reports errors when stores are modified during the cleanup phase
// (after shutdown completes but before map removal)
func TestUnregisterAllDataStoresCleanupPhaseErrors(t *testing.T) {
	t.Parallel()

	dsm := NewDataStoreManager(
		WithShutdownTimeout(2 * time.Second),
	)

	const numStores = 3
	const baseID DataStoreID = 12300

	// Register stores with very fast shutdown so we can control the cleanup phase timing
	for i := 0; i < numStores; i++ {
		storeID := baseID + DataStoreID(i)
		store := newMockDataStore(storeID, fmt.Sprintf("cleanup_test_store_%d", i))
		err := dsm.RegisterDataStore(store)
		assert.NoError(t, err, "Failed to register store %d", i)

		// Initialize each store
		err = dsm.ClaimDataStore(storeID, events.HookedSyscall)
		assert.NoError(t, err, "Failed to claim store %d", i)
		err = dsm.UnclaimDataStore(storeID, events.HookedSyscall)
		assert.NoError(t, err, "Failed to unclaim store %d", i)
	}

	// Use a slow store that will give us time to interfere during cleanup
	slowStoreID := baseID + DataStoreID(numStores)
	slowStore := newSlowDataStore(slowStoreID, "slow_cleanup_store", 0, 0, 500*time.Millisecond)
	err := dsm.RegisterDataStore(slowStore)
	assert.NoError(t, err, "Failed to register slow store")

	err = dsm.ClaimDataStore(slowStoreID, events.HookedSyscall)
	assert.NoError(t, err, "Failed to claim slow store")
	err = dsm.UnclaimDataStore(slowStoreID, events.HookedSyscall)
	assert.NoError(t, err, "Failed to unclaim slow store")

	var wg sync.WaitGroup
	wg.Add(2)

	var unregisterAllErr error

	// Goroutine 1: UnregisterAll (slow store will delay the operation)
	go func() {
		defer wg.Done()
		unregisterAllErr = dsm.UnregisterAllDataStores(false)
	}()

	// Goroutine 2: Interfere during the operation
	go func() {
		defer wg.Done()
		time.Sleep(150 * time.Millisecond) // Wait for fast stores to shutdown

		// Try to unregister one of the fast stores that already shut down
		// This simulates another goroutine removing a store during cleanup
		_ = dsm.UnregisterDataStore(baseID, true)

		// Try to re-register another store with same ID
		newStore := newMockDataStore(baseID+1, "replacement_store")
		_ = dsm.RegisterDataStore(newStore)
	}()

	wg.Wait()

	// Should have errors from the concurrent modifications during cleanup
	if unregisterAllErr != nil {
		t.Logf("UnregisterAll returned error (expected): %v", unregisterAllErr)
		// Verify that the error contains our specific cleanup-phase errors
		assert.True(t,
			errors.Is(unregisterAllErr, ErrDataStoreUnregisteredDuringOperation) ||
				errors.Is(unregisterAllErr, ErrDataStoreReRegistered),
			"Error should contain cleanup-phase concurrency errors")
	}

	// Final cleanup
	_ = dsm.UnregisterAllDataStores(true)
}

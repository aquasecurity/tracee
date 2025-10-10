package datastore

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/goleak"

	"github.com/aquasecurity/tracee/pkg/events"
)

// TestConcurrentClaimDifferentStores verifies thread-safe claims across multiple stores
func TestConcurrentClaimDifferentStores(t *testing.T) {
	defer goleak.VerifyNone(t)

	dsm := NewDataStoreManager()
	const numStores = 10
	const numGoroutines = 20

	// Register multiple stores
	for i := 0; i < numStores; i++ {
		err := dsm.RegisterDataStore(newMockDataStore(DataStoreID(20000+i), "concurrent_store"))
		assert.NoError(t, err)
	}

	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	start := make(chan struct{})

	// Multiple goroutines claiming different stores
	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start // Wait for start signal

			storeID := DataStoreID(20000 + (idx % numStores))
			eventID := events.ID(1000 + idx)

			err := dsm.ClaimDataStore(storeID, eventID)
			assert.NoError(t, err)

			// Verify we can get the store
			store, err := dsm.GetDataStore(storeID)
			assert.NoError(t, err)
			assert.NotNil(t, store)
		}(i)
	}

	close(start) // Release all goroutines at once
	wg.Wait()

	// Cleanup
	for i := 0; i < numGoroutines; i++ {
		storeID := DataStoreID(20000 + (i % numStores))
		eventID := events.ID(1000 + i)
		_ = dsm.UnclaimDataStore(storeID, eventID)
	}

	for i := 0; i < numStores; i++ {
		_ = dsm.UnregisterDataStore(DataStoreID(20000+i), false)
	}
}

// TestConcurrentClaimSameStore verifies thread-safe claims on a single store by multiple events
func TestConcurrentClaimSameStore(t *testing.T) {
	defer goleak.VerifyNone(t)

	dsm := NewDataStoreManager()
	const storeID DataStoreID = 20100
	const numGoroutines = 50

	err := dsm.RegisterDataStore(newMockDataStore(storeID, "shared_store"))
	assert.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	start := make(chan struct{})

	// Multiple goroutines claiming the same store with different events
	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start // Wait for start signal

			eventID := events.ID(2000 + idx)

			err := dsm.ClaimDataStore(storeID, eventID)
			assert.NoError(t, err)
		}(i)
	}

	close(start) // Release all goroutines at once
	wg.Wait()

	// Verify all claims registered
	status, err := dsm.GetDataStoreStatus(storeID)
	assert.NoError(t, err)
	assert.Equal(t, numGoroutines, len(status.ClaimedBy))

	// Cleanup
	for i := 0; i < numGoroutines; i++ {
		eventID := events.ID(2000 + i)
		_ = dsm.UnclaimDataStore(storeID, eventID)
	}
	_ = dsm.UnregisterDataStore(storeID, false)
}

// TestConcurrentClaimUnclaim verifies thread-safe interleaved claim/unclaim operations
func TestConcurrentClaimUnclaim(t *testing.T) {
	defer goleak.VerifyNone(t)

	dsm := NewDataStoreManager()
	const storeID DataStoreID = 20200
	const numIterations = 100

	err := dsm.RegisterDataStore(newMockDataStore(storeID, "claim_unclaim_store"))
	assert.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(2)
	start := make(chan struct{})

	// Goroutine 1: Claim repeatedly
	go func() {
		defer wg.Done()
		<-start // Wait for start signal

		for i := 0; i < numIterations; i++ {
			eventID := events.ID(3000 + (i % 10))
			_ = dsm.ClaimDataStore(storeID, eventID)
			time.Sleep(time.Microsecond)
		}
	}()

	// Goroutine 2: Unclaim repeatedly
	go func() {
		defer wg.Done()
		<-start // Wait for start signal

		for i := 0; i < numIterations; i++ {
			eventID := events.ID(3000 + (i % 10))
			_ = dsm.UnclaimDataStore(storeID, eventID)
			time.Sleep(time.Microsecond)
		}
	}()

	close(start) // Release all goroutines at once
	wg.Wait()

	// Cleanup
	for i := 0; i < 10; i++ {
		_ = dsm.UnclaimDataStore(storeID, events.ID(3000+i))
	}
	_ = dsm.UnregisterDataStore(storeID, false)
}

// TestConcurrentGetWhileModifying verifies read operations don't block write operations
func TestConcurrentGetWhileModifying(t *testing.T) {
	defer goleak.VerifyNone(t)

	dsm := NewDataStoreManager()
	const numStores = 5
	const numReaders = 10
	const numWriters = 5
	const iterations = 50

	// Register stores
	for i := 0; i < numStores; i++ {
		err := dsm.RegisterDataStore(newMockDataStore(DataStoreID(20300+i), "get_modify_store"))
		assert.NoError(t, err)
	}

	var wg sync.WaitGroup
	wg.Add(numReaders + numWriters)
	start := make(chan struct{})

	// Reader goroutines
	for i := 0; i < numReaders; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start // Wait for start signal

			for j := 0; j < iterations; j++ {
				storeID := DataStoreID(20300 + (j % numStores))

				// Read operations
				_, _ = dsm.GetDataStoreStatus(storeID)
				_ = dsm.GetAllDataStoreStatuses()

				time.Sleep(time.Microsecond)
			}
		}(i)
	}

	// Writer goroutines
	for i := 0; i < numWriters; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start // Wait for start signal

			for j := 0; j < iterations; j++ {
				storeID := DataStoreID(20300 + (j % numStores))
				eventID := events.ID(4000 + idx)

				// Write operations
				_ = dsm.ClaimDataStore(storeID, eventID)
				time.Sleep(time.Microsecond)
				_ = dsm.UnclaimDataStore(storeID, eventID)
			}
		}(i)
	}

	close(start) // Release all goroutines at once
	wg.Wait()

	// Cleanup
	for i := 0; i < numStores; i++ {
		_ = dsm.UnregisterDataStore(DataStoreID(20300+i), false)
	}
}

// TestConcurrentResetWhileAccessing verifies forced reset operations with concurrent data access
func TestConcurrentResetWhileAccessing(t *testing.T) {
	defer goleak.VerifyNone(t)

	dsm := NewDataStoreManager()
	const storeID DataStoreID = 20400
	const numAccessors = 10
	const numResetters = 3
	const iterations = 30

	err := dsm.RegisterDataStore(newMockDataStore(storeID, "reset_access_store"))
	assert.NoError(t, err)

	// Claim by one event to allow access
	err = dsm.ClaimDataStore(storeID, events.HookedSyscall)
	assert.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(numAccessors + numResetters)
	start := make(chan struct{})

	// Accessor goroutines
	for i := 0; i < numAccessors; i++ {
		go func() {
			defer wg.Done()
			<-start // Wait for start signal

			for j := 0; j < iterations; j++ {
				store, err := dsm.GetDataStore(storeID)
				if err == nil {
					mockStore, ok := store.(*mockDataStore)
					assert.True(t, ok, "Expected datastore '%d' to be a mockDataStore", storeID)
					mockStore.Set("key", "value")
					_, _ = mockStore.Get("key")
					_ = mockStore.Len()
				}
				time.Sleep(time.Microsecond)
			}
		}()
	}

	// Resetter goroutines
	for i := 0; i < numResetters; i++ {
		go func() {
			defer wg.Done()
			<-start // Wait for start signal

			for j := 0; j < iterations; j++ {
				_ = dsm.ResetDataStore(storeID, true) // Force reset
				time.Sleep(100 * time.Microsecond)
			}
		}()
	}

	close(start) // Release all goroutines at once
	wg.Wait()

	// Cleanup
	_ = dsm.UnclaimDataStore(storeID, events.HookedSyscall)
	_ = dsm.UnregisterDataStore(storeID, false)
}

// TestConcurrentRegisterUnregister verifies graceful handling of concurrent lifecycle operations
// Non-deterministic: operations may fail due to concurrent state changes, which is expected behavior
func TestConcurrentRegisterUnregister(t *testing.T) {
	defer goleak.VerifyNone(t)

	dsm := NewDataStoreManager()
	const numStores = 20
	const iterations = 100 // Non-deterministic: register may fail if already registered

	var wg sync.WaitGroup
	wg.Add(numStores)
	start := make(chan struct{})

	for i := 0; i < numStores; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start // Wait for start signal

			storeID := DataStoreID(20500 + idx)

			for j := 0; j < iterations; j++ {
				// Register
				store := newMockDataStore(storeID, "register_unregister_store")
				err := dsm.RegisterDataStore(store)
				if err != nil {
					continue // Already registered (expected in concurrent scenario)
				}

				// Claim and use
				eventID := events.ID(5000 + idx)
				_ = dsm.ClaimDataStore(storeID, eventID)

				// Access store
				s, err := dsm.GetDataStore(storeID)
				if err == nil {
					ms, ok := s.(*mockDataStore)
					assert.True(t, ok, "Expected datastore '%d' to be a mockDataStore", storeID)
					ms.Set("test", "data")
				}

				// Unclaim and unregister
				_ = dsm.UnclaimDataStore(storeID, eventID)
				_ = dsm.UnregisterDataStore(storeID, false)

				time.Sleep(10 * time.Microsecond) // Small delay to allow other goroutines to interleave
			}
		}(i)
	}

	close(start) // Release all goroutines at once
	wg.Wait()

	// Verify all cleaned up
	statuses := dsm.GetAllDataStoreStatuses()
	assert.Equal(t, 0, len(statuses), "All stores should be unregistered")
}

// TestConcurrentResetAllWhileUsing verifies ResetAllDataStores with concurrent data access
func TestConcurrentResetAllWhileUsing(t *testing.T) {
	defer goleak.VerifyNone(t)

	dsm := NewDataStoreManager()
	const numStores = 10
	const numUsers = 15
	const iterations = 20

	// Register stores
	for i := 0; i < numStores; i++ {
		err := dsm.RegisterDataStore(newMockDataStore(DataStoreID(20600+i), "reset_all_store"))
		assert.NoError(t, err)
	}

	// Claim all stores
	for i := 0; i < numStores; i++ {
		_ = dsm.ClaimDataStore(DataStoreID(20600+i), events.HookedSyscall)
	}

	var wg sync.WaitGroup
	wg.Add(numUsers + 1)
	start := make(chan struct{})

	// User goroutines
	for i := 0; i < numUsers; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start // Wait for start signal

			for j := 0; j < iterations; j++ {
				storeID := DataStoreID(20600 + (j % numStores))

				store, err := dsm.GetDataStore(storeID)
				if err == nil {
					mockStore, ok := store.(*mockDataStore)
					assert.True(t, ok, "Expected datastore '%d' to be a mockDataStore", storeID)
					mockStore.Set("key"+string(rune(idx)), "value")
					_ = mockStore.Len()
				}
				time.Sleep(time.Microsecond)
			}
		}(i)
	}

	// Reset all goroutine
	go func() {
		defer wg.Done()
		<-start // Wait for start signal

		for i := 0; i < iterations; i++ {
			_ = dsm.ResetAllDataStores(true) // Force reset
			time.Sleep(time.Millisecond)
		}
	}()

	close(start) // Release all goroutines at once
	wg.Wait()

	// Cleanup
	for i := 0; i < numStores; i++ {
		_ = dsm.UnclaimDataStore(DataStoreID(20600+i), events.HookedSyscall)
		_ = dsm.UnregisterDataStore(DataStoreID(20600+i), false)
	}
}

// TestConcurrentUnregisterAllWhileUsing verifies UnregisterAllDataStores with concurrent data access
func TestConcurrentUnregisterAllWhileUsing(t *testing.T) {
	defer goleak.VerifyNone(t)

	dsm := NewDataStoreManager()
	const numStores = 10
	const numUsers = 10

	// Register stores
	for i := 0; i < numStores; i++ {
		err := dsm.RegisterDataStore(newMockDataStore(DataStoreID(20700+i), "unregister_all_store"))
		assert.NoError(t, err)
	}

	// Claim all stores
	for i := 0; i < numStores; i++ {
		_ = dsm.ClaimDataStore(DataStoreID(20700+i), events.HookedSyscall)
	}

	var wg sync.WaitGroup
	wg.Add(numUsers + 1)
	start := make(chan struct{})

	// User goroutines
	for i := 0; i < numUsers; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start // Wait for start signal

			for j := 0; j < 50; j++ {
				storeID := DataStoreID(20700 + (j % numStores))

				store, err := dsm.GetDataStore(storeID)
				if err == nil {
					mockStore, ok := store.(*mockDataStore)
					assert.True(t, ok, "Expected datastore '%d' to be a mockDataStore", storeID)
					mockStore.Set("key", "value")
					_ = mockStore.Len()
				}
				time.Sleep(time.Microsecond)
			}
		}(i)
	}

	// Unregister all goroutine
	go func() {
		defer wg.Done()
		<-start // Wait for start signal

		time.Sleep(10 * time.Millisecond) // Let users run for a bit
		_ = dsm.UnregisterAllDataStores(true)
	}()

	close(start) // Release all goroutines at once
	wg.Wait()

	// Verify all unregistered
	statuses := dsm.GetAllDataStoreStatuses()
	assert.Equal(t, 0, len(statuses), "All stores should be unregistered")
}

// TestConcurrentMixedOperations verifies system stability under realistic concurrent workload
// Non-deterministic: success rate varies with timing (30,000 operations across 30 goroutines)
// Operations may fail gracefully due to concurrent state changes, validating error handling
func TestConcurrentMixedOperations(t *testing.T) {
	defer goleak.VerifyNone(t)

	dsm := NewDataStoreManager()
	const numStores = 15
	const numGoroutines = 30
	const iterations = 1000 // Non-deterministic: success count varies with timing

	// Pre-register some stores
	for i := 0; i < numStores/2; i++ {
		err := dsm.RegisterDataStore(newMockDataStore(DataStoreID(20800+i), "mixed_store"))
		assert.NoError(t, err)
	}

	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	start := make(chan struct{})
	var successfulOps int64

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start // Wait for start signal

			for j := 0; j < iterations; j++ {
				storeID := DataStoreID(20800 + (j % numStores))
				eventID := events.ID(7000 + idx)

				// Mix of operations
				switch j % 8 {
				case 0: // Register
					store := newMockDataStore(storeID, "mixed_store")
					if dsm.RegisterDataStore(store) == nil {
						atomic.AddInt64(&successfulOps, 1)
					}

				case 1: // Claim
					if dsm.ClaimDataStore(storeID, eventID) == nil {
						atomic.AddInt64(&successfulOps, 1)
					}

				case 2: // Get and use
					store, err := dsm.GetDataStore(storeID)
					if err == nil {
						mockStore, ok := store.(*mockDataStore)
						assert.True(t, ok, "Expected datastore '%d' to be a mockDataStore", storeID)
						mockStore.Set("key", "value")
						_, _ = mockStore.Get("key")
						atomic.AddInt64(&successfulOps, 1)
					}

				case 3: // Unclaim
					if dsm.UnclaimDataStore(storeID, eventID) == nil {
						atomic.AddInt64(&successfulOps, 1)
					}

				case 4: // Get status
					_, err := dsm.GetDataStoreStatus(storeID)
					if err == nil {
						atomic.AddInt64(&successfulOps, 1)
					}

				case 5: // Get all statuses
					_ = dsm.GetAllDataStoreStatuses()
					atomic.AddInt64(&successfulOps, 1)

				case 6: // Reset
					if dsm.ResetDataStore(storeID, false) == nil {
						atomic.AddInt64(&successfulOps, 1)
					}

				case 7: // Unregister
					if dsm.UnregisterDataStore(storeID, false) == nil {
						atomic.AddInt64(&successfulOps, 1)
					}
				}

				time.Sleep(time.Microsecond)
			}
		}(i)
	}

	close(start) // Release all goroutines at once
	wg.Wait()

	// Success rate varies (typically 55-65% of 30K ops) due to intentional race conditions
	// between 30 goroutines competing for 15 stores. This validates graceful conflict handling.
	t.Logf("Successful operations: %d out of %d total (%.1f%% success rate - expected variation)",
		successfulOps, numGoroutines*iterations, float64(successfulOps)/float64(numGoroutines*iterations)*100)

	// Cleanup any remaining
	_ = dsm.UnregisterAllDataStores(true)
}

// TestConcurrentStoreDataAccess verifies DataStore internal thread-safety with concurrent reads/writes
func TestConcurrentStoreDataAccess(t *testing.T) {
	defer goleak.VerifyNone(t)

	dsm := NewDataStoreManager()
	const storeID DataStoreID = 20900
	const numWriters = 10
	const numReaders = 20
	const iterations = 100

	err := dsm.RegisterDataStore(newMockDataStore(storeID, "data_access_store"))
	assert.NoError(t, err)

	err = dsm.ClaimDataStore(storeID, events.HookedSyscall)
	assert.NoError(t, err)

	store, err := dsm.GetDataStore(storeID)
	assert.NoError(t, err)
	mockStore, ok := store.(*mockDataStore)
	assert.True(t, ok, "Expected datastore '%d' to be a mockDataStore", storeID)

	var wg sync.WaitGroup
	wg.Add(numWriters + numReaders)
	start := make(chan struct{})

	// Writer goroutines
	for i := 0; i < numWriters; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start // Wait for start signal

			for j := 0; j < iterations; j++ {
				key := "key_" + string(rune(idx))
				value := "value_" + string(rune(j))
				mockStore.Set(key, value)
				time.Sleep(time.Microsecond)
			}
		}(i)
	}

	// Reader goroutines
	for i := 0; i < numReaders; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start // Wait for start signal

			for j := 0; j < iterations; j++ {
				key := "key_" + string(rune(idx%numWriters))
				_, _ = mockStore.Get(key)
				_ = mockStore.Len()
				time.Sleep(time.Microsecond)
			}
		}(i)
	}

	close(start) // Release all goroutines at once
	wg.Wait()

	// Cleanup
	_ = dsm.UnclaimDataStore(storeID, events.HookedSyscall)
	_ = dsm.UnregisterDataStore(storeID, false)
}

// TestConcurrentStatusQueries verifies read lock efficiency under high query load
func TestConcurrentStatusQueries(t *testing.T) {
	defer goleak.VerifyNone(t)

	dsm := NewDataStoreManager()
	const numStores = 20
	const numQueriers = 50
	const iterations = 100

	// Register and claim stores
	for i := 0; i < numStores; i++ {
		err := dsm.RegisterDataStore(newMockDataStore(DataStoreID(21000+i), "status_store"))
		assert.NoError(t, err)
		_ = dsm.ClaimDataStore(DataStoreID(21000+i), events.HookedSyscall)
	}

	var wg sync.WaitGroup
	wg.Add(numQueriers)
	start := make(chan struct{})

	for i := 0; i < numQueriers; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start // Wait for start signal

			for j := 0; j < iterations; j++ {
				// Query individual statuses
				storeID := DataStoreID(21000 + (j % numStores))
				_, _ = dsm.GetDataStoreStatus(storeID)

				// Query all statuses
				statuses := dsm.GetAllDataStoreStatuses()
				assert.LessOrEqual(t, len(statuses), numStores)

				time.Sleep(time.Microsecond)
			}
		}(i)
	}

	close(start) // Release all goroutines at once
	wg.Wait()

	// Cleanup
	for i := 0; i < numStores; i++ {
		_ = dsm.UnclaimDataStore(DataStoreID(21000+i), events.HookedSyscall)
		_ = dsm.UnregisterDataStore(DataStoreID(21000+i), false)
	}
}

// TestConcurrentIdempotentOperations verifies idempotent behavior under concurrent calls
func TestConcurrentIdempotentOperations(t *testing.T) {
	defer goleak.VerifyNone(t)

	dsm := NewDataStoreManager()
	const storeID DataStoreID = 21100
	const numGoroutines = 30
	const iterations = 50

	err := dsm.RegisterDataStore(newMockDataStore(storeID, "idempotent_store"))
	assert.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(numGoroutines * 2)
	start := make(chan struct{})

	// Multiple goroutines claiming the same event (idempotent)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			<-start // Wait for start signal

			for j := 0; j < iterations; j++ {
				err := dsm.ClaimDataStore(storeID, events.HookedSyscall)
				assert.NoError(t, err, "Idempotent claim should not error")
			}
		}()
	}

	// Multiple goroutines unclaiming (idempotent)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			<-start // Wait for start signal

			time.Sleep(time.Millisecond) // Let some claims happen first
			for j := 0; j < iterations; j++ {
				err := dsm.UnclaimDataStore(storeID, events.SymbolsLoaded)
				assert.NoError(t, err, "Idempotent unclaim should not error")
			}
		}()
	}

	close(start) // Release all goroutines at once
	wg.Wait()

	// Cleanup
	_ = dsm.UnclaimDataStore(storeID, events.HookedSyscall)
	_ = dsm.UnregisterDataStore(storeID, false)
}

// TestConcurrentStressTest validates system stability under extreme load (500,000 operations)
// Non-deterministic: operations may fail gracefully, validates no deadlocks or panics occur
// Skipped in short mode (-short flag)
func TestConcurrentStressTest(t *testing.T) {
	defer goleak.VerifyNone(t)

	if testing.Short() {
		t.Skip("Skipping stress test in short mode (500,000 operations)")
	}

	dsm := NewDataStoreManager()
	const numStores = 50
	const numGoroutines = 100
	const iterations = 5000 // Non-deterministic: operations may succeed or fail (500K total ops)

	// Register initial stores
	for i := 0; i < numStores/2; i++ {
		_ = dsm.RegisterDataStore(newMockDataStore(DataStoreID(21200+i), "stress_store"))
	}

	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	start := make(chan struct{})
	var totalOps int64

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start // Wait for start signal

			for j := 0; j < iterations; j++ {
				storeID := DataStoreID(21200 + (j % numStores))
				eventID := events.ID(9000 + idx)

				// Random operations
				op := (idx + j) % 10
				switch op {
				case 0, 1: // Register
					store := newMockDataStore(storeID, "stress_store")
					_ = dsm.RegisterDataStore(store)

				case 2, 3: // Claim
					_ = dsm.ClaimDataStore(storeID, eventID)

				case 4: // Get and access
					store, err := dsm.GetDataStore(storeID)
					if err == nil {
						ms, ok := store.(*mockDataStore)
						assert.True(t, ok, "Expected datastore '%d' to be a mockDataStore", storeID)
						ms.Set("k", "v")
						_, _ = ms.Get("k")
					}

				case 5: // Unclaim
					_ = dsm.UnclaimDataStore(storeID, eventID)

				case 6: // Status
					_, _ = dsm.GetDataStoreStatus(storeID)

				case 7: // All statuses
					_ = dsm.GetAllDataStoreStatuses()

				case 8: // Reset
					_ = dsm.ResetDataStore(storeID, false)

				case 9: // Unregister
					_ = dsm.UnregisterDataStore(storeID, false)
				}

				atomic.AddInt64(&totalOps, 1)
			}
		}(i)
	}

	close(start) // Release all goroutines at once
	wg.Wait()

	t.Logf("Completed %d operations - validates stability under extreme load", totalOps)

	// Force cleanup
	for i := 0; i < numStores; i++ {
		for j := 0; j < numGoroutines; j++ {
			_ = dsm.UnclaimDataStore(DataStoreID(21200+i), events.ID(9000+j))
		}
		_ = dsm.UnregisterDataStore(DataStoreID(21200+i), true)
	}

	statuses := dsm.GetAllDataStoreStatuses()
	assert.Equal(t, 0, len(statuses), "All stores should be cleaned up")
}

// TestAllMethodsSimultaneously verifies all manager methods can execute concurrently without deadlock
// Non-deterministic: operations may fail, but test must complete within timeout (30s)
// Failure to complete indicates deadlock or livelock
func TestAllMethodsSimultaneously(t *testing.T) {
	defer goleak.VerifyNone(t)

	dsm := NewDataStoreManager(
		WithInitTimeout(1*time.Second),
		WithResetTimeout(1*time.Second),
		WithShutdownTimeout(1*time.Second),
	)

	const numStores = 10
	const iterations = 1000 // Non-deterministic: operations may succeed or fail

	// Pre-register some stores
	for i := 0; i < numStores; i++ {
		_ = dsm.RegisterDataStore(newMockDataStore(DataStoreID(21300+i), "all_methods_store"))
	}

	// Claim some stores
	for i := 0; i < numStores/2; i++ {
		_ = dsm.ClaimDataStore(DataStoreID(21300+i), events.HookedSyscall)
	}

	// Channel to detect test completion
	done := make(chan struct{})
	timeout := time.After(30 * time.Second)

	var wg sync.WaitGroup
	start := make(chan struct{})

	// Goroutine for each DataStoreManager method
	methodCount := 0

	// RegisterDataStore
	methodCount++
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start // Wait for start signal

		for i := 0; i < iterations; i++ {
			storeID := DataStoreID(21400 + (i % 20))
			_ = dsm.RegisterDataStore(newMockDataStore(storeID, "method_test"))
			time.Sleep(time.Microsecond * 100)
		}
	}()

	// UnregisterDataStore
	methodCount++
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start // Wait for start signal

		for i := 0; i < iterations; i++ {
			storeID := DataStoreID(21400 + (i % 20))
			_ = dsm.UnregisterDataStore(storeID, false)
			time.Sleep(time.Microsecond * 100)
		}
	}()

	// ClaimDataStore
	methodCount++
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start // Wait for start signal

		for i := 0; i < iterations; i++ {
			storeID := DataStoreID(21300 + (i % numStores))
			eventID := events.ID(10000 + (i % 50))
			_ = dsm.ClaimDataStore(storeID, eventID)
			time.Sleep(time.Microsecond * 100)
		}
	}()

	// UnclaimDataStore
	methodCount++
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start // Wait for start signal

		for i := 0; i < iterations; i++ {
			storeID := DataStoreID(21300 + (i % numStores))
			eventID := events.ID(10000 + (i % 50))
			_ = dsm.UnclaimDataStore(storeID, eventID)
			time.Sleep(time.Microsecond * 100)
		}
	}()

	// ResetDataStore
	methodCount++
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start // Wait for start signal

		for i := 0; i < iterations; i++ {
			storeID := DataStoreID(21300 + (i % numStores))
			_ = dsm.ResetDataStore(storeID, false)
			time.Sleep(time.Microsecond * 100)
		}
	}()

	// ResetAllDataStores
	methodCount++
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start // Wait for start signal

		for i := 0; i < iterations/10; i++ {
			_ = dsm.ResetAllDataStores(false)
			time.Sleep(time.Millisecond)
		}
	}()

	// UnregisterAllDataStores
	methodCount++
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start // Wait for start signal

		for i := 0; i < iterations/10; i++ {
			_ = dsm.UnregisterAllDataStores(false)
			time.Sleep(time.Millisecond)
		}
	}()

	// GetDataStore
	methodCount++
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start // Wait for start signal

		for i := 0; i < iterations; i++ {
			storeID := DataStoreID(21300 + (i % numStores))
			_, _ = dsm.GetDataStore(storeID)
			time.Sleep(time.Microsecond * 100)
		}
	}()

	// GetDataStoreStatus
	methodCount++
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start // Wait for start signal

		for i := 0; i < iterations; i++ {
			storeID := DataStoreID(21300 + (i % numStores))
			_, _ = dsm.GetDataStoreStatus(storeID)
			time.Sleep(time.Microsecond * 100)
		}
	}()

	// GetAllDataStoreStatuses
	methodCount++
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start // Wait for start signal

		for i := 0; i < iterations; i++ {
			_ = dsm.GetAllDataStoreStatuses()
			time.Sleep(time.Microsecond * 100)
		}
	}()

	// DataStore method access goroutines
	for methodIdx := 0; methodIdx < 5; methodIdx++ {
		methodCount++
		wg.Add(1)
		go func(mIdx int) {
			defer wg.Done()
			<-start // Wait for start signal

			for i := 0; i < iterations; i++ {
				storeID := DataStoreID(21300 + (i % numStores))
				store, err := dsm.GetDataStore(storeID)
				if err == nil {
					mockStore, ok := store.(*mockDataStore)
					assert.True(t, ok, "Expected datastore '%d' to be a mockDataStore", storeID)

					// Call different DataStore methods
					switch mIdx {
					case 0: // Initialize
						_ = mockStore.Initialize()
					case 1: // Reset
						_ = mockStore.Reset()
					case 2: // Shutdown
						_ = mockStore.Shutdown()
					case 3: // Data access
						mockStore.Set("key", "value")
						_, _ = mockStore.Get("key")
					case 4: // Info methods
						_ = mockStore.ID()
						_ = mockStore.Name()
						_ = mockStore.Len()
					}
				}
				time.Sleep(time.Microsecond * 100)
			}
		}(methodIdx)
	}

	// Release all goroutines at once
	close(start)

	// Wait for completion or timeout
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		t.Logf("Test completed successfully with %d concurrent method goroutines", methodCount)
	case <-timeout:
		t.Fatal("Test timed out - possible deadlock or blocking detected")
	}

	// Cleanup
	for i := 0; i < 50; i++ {
		for j := 0; j < numStores; j++ {
			_ = dsm.UnclaimDataStore(DataStoreID(21300+j), events.ID(10000+i))
		}
	}
	_ = dsm.UnregisterAllDataStores(true)
}

// TestDeadlockDetection validates deadlock-free operation under pathological concurrent patterns
// Non-deterministic: operations may fail, but test must complete within timeout (30s)
// Tests worst-case scenarios: claim during unregister, reset during claim, concurrent access during reset
func TestDeadlockDetection(t *testing.T) {
	defer goleak.VerifyNone(t)

	dsm := NewDataStoreManager(
		WithInitTimeout(500*time.Millisecond),
		WithResetTimeout(500*time.Millisecond),
		WithShutdownTimeout(500*time.Millisecond),
	)

	const numStores = 5

	// Register stores
	for i := 0; i < numStores; i++ {
		_ = dsm.RegisterDataStore(newMockDataStore(DataStoreID(21500+i), "deadlock_test"))
		_ = dsm.ClaimDataStore(DataStoreID(21500+i), events.HookedSyscall)
	}

	timeout := time.After(30 * time.Second) // Extended timeout for 1000 iterations
	done := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(4)
	start := make(chan struct{})

	// Scenario 1: Claim while unregistering (non-deterministic)
	go func() {
		defer wg.Done()
		<-start // Wait for start signal

		for i := 0; i < 1000; i++ {
			storeID := DataStoreID(21500 + (i % numStores))
			_ = dsm.ClaimDataStore(storeID, events.ID(11000+i))
			_ = dsm.UnregisterDataStore(storeID, true)
			_ = dsm.RegisterDataStore(newMockDataStore(storeID, "deadlock_test"))
		}
	}()

	// Scenario 2: Reset while claiming (non-deterministic)
	go func() {
		defer wg.Done()
		<-start // Wait for start signal

		for i := 0; i < 1000; i++ {
			storeID := DataStoreID(21500 + (i % numStores))
			_ = dsm.ResetDataStore(storeID, true)
			_ = dsm.ClaimDataStore(storeID, events.ID(11100+i))
		}
	}()

	// Scenario 3: Read status while modifying (deterministic reads)
	go func() {
		defer wg.Done()
		<-start // Wait for start signal

		for i := 0; i < 2000; i++ {
			storeID := DataStoreID(21500 + (i % numStores))
			_, _ = dsm.GetDataStoreStatus(storeID)
			_ = dsm.GetAllDataStoreStatuses()
		}
	}()

	// Scenario 4: Access store data while resetting (non-deterministic)
	go func() {
		defer wg.Done()
		<-start // Wait for start signal

		for i := 0; i < 1000; i++ {
			storeID := DataStoreID(21500 + (i % numStores))
			store, err := dsm.GetDataStore(storeID)
			if err == nil {
				ms, ok := store.(*mockDataStore)
				assert.True(t, ok, "Expected datastore '%d' to be a mockDataStore", storeID)
				ms.Set("k", "v")
				_, _ = ms.Get("k")
				_ = ms.Len()
			}
			_ = dsm.ResetDataStore(storeID, true)
		}
	}()

	// Release all goroutines at once
	close(start)

	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		t.Log("Deadlock detection test passed - no deadlocks detected")
	case <-timeout:
		t.Fatal("Deadlock detected - test timed out")
	}

	// Cleanup
	_ = dsm.UnregisterAllDataStores(true)
}

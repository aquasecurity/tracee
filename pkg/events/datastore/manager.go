package datastore

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/events"
)

// DataStoreID - integer identifier for data stores (for fast lookups)
type DataStoreID int32

// String returns a string representation of DataStoreID for logging
func (id DataStoreID) String() string {
	return fmt.Sprintf("DataStoreID(%d)", id)
}

//
// Error types for data store operations
//

var (
	// ErrDataStoreNotRegistered is returned when attempting to access an unregistered store
	ErrDataStoreNotRegistered = errors.New("datastore not registered")

	// ErrDataStoreAlreadyRegistered is returned when attempting to register a store with a duplicate ID
	ErrDataStoreAlreadyRegistered = errors.New("datastore already registered")

	// ErrDataStoreNotClaimed is returned when attempting to get a store that has no claims
	ErrDataStoreNotClaimed = errors.New("datastore not claimed by any event")

	// ErrDataStoreClaimed is returned when attempting to reset/unregister a claimed store without force
	ErrDataStoreClaimed = errors.New("datastore has active claims")

	// ErrDataStoreUnregisteredDuringOperation is returned when a store is unregistered during a lifecycle operation
	ErrDataStoreUnregisteredDuringOperation = errors.New("datastore was unregistered during operation")

	// ErrDataStoreReRegistered is returned when a store is re-registered with different instance during operation
	ErrDataStoreReRegistered = errors.New("datastore was re-registered with different instance")

	// ErrDataStoreTimeout is returned when a store operation times out
	ErrDataStoreTimeout = errors.New("datastore operation timed out")
)

// Default timeout values for lifecycle operations
const (
	DefaultInitTimeout     = 5 * time.Second
	DefaultResetTimeout    = 5 * time.Second
	DefaultShutdownTimeout = 10 * time.Second
)

// DataStore - base interface for all data stores
//
// Lifecycle Contract:
// All lifecycle methods (Initialize, Reset, Shutdown) MUST be idempotent.
// Implementations must ensure:
//   - Initialize() can be called multiple times safely (no-op if already initialized)
//   - Reset() can be called multiple times safely (no-op if not initialized)
//   - Shutdown() can be called multiple times safely (no-op if already shut down)
//
// This contract allows the manager to call these methods without complex state tracking
// and prevents TOCTOU races when stores are accessed concurrently.
//
// Thread-Safety Contract:
// Implementations MUST provide their own concurrency control for mutable internal state.
// Methods that access or modify mutable state (Initialize, Reset, Shutdown, Len, and any
// custom data access methods) must be thread-safe as they may be called concurrently.
// Methods returning immutable values (ID, Name) typically don't require synchronization.
// The manager only protects its own state (store registry and claims), not the DataStore's
// internal data.
type DataStore interface {
	// Initialize allocates and prepares the store (idempotent)
	Initialize() error

	// Reset clears data but keeps the store allocated (idempotent)
	Reset() error

	// Shutdown deallocates the store completely (idempotent)
	Shutdown() error

	// ID returns the store's unique identifier
	ID() DataStoreID

	// Name returns the store name for logging and debugging
	Name() string

	// Len returns the number of elements in the store (0 if not initialized)
	Len() int
}

// managedDataStore - wraps a DataStore with claim tracking
type managedDataStore struct {
	store  DataStore
	claims map[events.ID]struct{} // which events have claimed this store
}

// DataStoreManager - coordinates data stores with claim tracking
// Uses coarse-grained locking: single mutex protects all manager state
// Provides timeout protection for all lifecycle operations
type DataStoreManager struct {
	stores          map[DataStoreID]*managedDataStore
	mu              sync.RWMutex // protects all manager state (stores map, claims, timeouts)
	initTimeout     time.Duration
	resetTimeout    time.Duration
	shutdownTimeout time.Duration
}

// Option configures a DataStoreManager
type Option func(*DataStoreManager)

// WithInitTimeout configures the timeout for Initialize operations
func WithInitTimeout(timeout time.Duration) Option {
	return func(dsm *DataStoreManager) {
		if timeout > 0 {
			dsm.initTimeout = timeout
		}
	}
}

// WithResetTimeout configures the timeout for Reset operations
func WithResetTimeout(timeout time.Duration) Option {
	return func(dsm *DataStoreManager) {
		if timeout > 0 {
			dsm.resetTimeout = timeout
		}
	}
}

// WithShutdownTimeout configures the timeout for Shutdown operations
func WithShutdownTimeout(timeout time.Duration) Option {
	return func(dsm *DataStoreManager) {
		if timeout > 0 {
			dsm.shutdownTimeout = timeout
		}
	}
}

// NewDataStoreManager creates a new data store manager with optional configuration
// Uses default timeouts unless overridden by options
func NewDataStoreManager(opts ...Option) *DataStoreManager {
	dsm := &DataStoreManager{
		stores:          make(map[DataStoreID]*managedDataStore),
		initTimeout:     DefaultInitTimeout,
		resetTimeout:    DefaultResetTimeout,
		shutdownTimeout: DefaultShutdownTimeout,
	}

	for _, opt := range opts {
		opt(dsm)
	}

	return dsm
}

// executeWithTimeout wraps a DataStore lifecycle operation with timeout protection
// Returns ErrDataStoreTimeout if the operation exceeds the timeout duration
func executeWithTimeout(
	storeName string,
	operation string,
	timeout time.Duration,
	fn func() error,
) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	done := make(chan error, 1)

	go func() {
		done <- fn()
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return errfmt.WrapError(fmt.Errorf("%w: %s %s operation after %v", ErrDataStoreTimeout, storeName, operation, timeout))
		}

		return ctx.Err() // context.Canceled or other context errors
	}
}

// RegisterDataStore adds a store to the manager
// The store is not initialized until first claimed by an event
func (dsm *DataStoreManager) RegisterDataStore(store DataStore) error {
	dsm.mu.Lock()
	defer dsm.mu.Unlock()

	id := store.ID()

	_, exists := dsm.stores[id]
	if exists {
		return errfmt.WrapError(fmt.Errorf("%w: %s (%d)", ErrDataStoreAlreadyRegistered, store.Name(), id))
	}

	dsm.stores[id] = &managedDataStore{
		store:  store,
		claims: make(map[events.ID]struct{}),
	}

	logger.Debugw("datastore was registered", "id", id, "name", store.Name())
	return nil
}

// ClaimDataStore claims a store for an event, initializing it if needed
// Idempotent: succeeds if already claimed by the same event
// Returns error if store was unregistered or re-registered during initialization
func (dsm *DataStoreManager) ClaimDataStore(storeID DataStoreID, eventID events.ID) error {
	dsm.mu.RLock()
	managed, exists := dsm.stores[storeID]
	if !exists {
		dsm.mu.RUnlock()
		return errfmt.WrapError(fmt.Errorf("%w: %d", ErrDataStoreNotRegistered, storeID))
	}

	// Check if already claimed (idempotent)
	_, claimed := managed.claims[eventID]
	if claimed {
		dsm.mu.RUnlock()
		return nil
	}

	store := managed.store
	initTimeout := dsm.initTimeout
	dsm.mu.RUnlock()

	// Execute Initialize without holding manager locks (store may use internal locking)
	err := executeWithTimeout(store.Name(), "initialize", initTimeout, store.Initialize)
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Add claim
	dsm.mu.Lock()
	defer dsm.mu.Unlock()

	// Re-check store still exists and add claim
	managedAfter, exists := dsm.stores[storeID]
	if !exists {
		return errfmt.WrapError(fmt.Errorf("%w: %d during initialization", ErrDataStoreUnregisteredDuringOperation, storeID))
	}
	if managedAfter != managed {
		return errfmt.WrapError(fmt.Errorf("%w: %d during initialization", ErrDataStoreReRegistered, storeID))
	}

	// Idempotent check (another goroutine might have claimed)
	_, claimed = managedAfter.claims[eventID]
	if !claimed {
		managedAfter.claims[eventID] = struct{}{}

		logger.Debugw("datastore was claimed by event",
			"id", storeID,
			"name", managedAfter.store.Name(),
			"event", eventID,
			"active_claims", len(managedAfter.claims))
	}

	return nil
}

// UnclaimDataStore removes an event's claim on a store (does not shut down the store)
// Idempotent: succeeds if not claimed by the event
func (dsm *DataStoreManager) UnclaimDataStore(storeID DataStoreID, eventID events.ID) error {
	dsm.mu.Lock()
	defer dsm.mu.Unlock()

	managed, exists := dsm.stores[storeID]
	if !exists {
		return errfmt.WrapError(fmt.Errorf("%w: %d", ErrDataStoreNotRegistered, storeID))
	}
	_, claimed := managed.claims[eventID]
	if !claimed {
		return nil
	}

	delete(managed.claims, eventID)

	logger.Debugw("datastore was unclaimed",
		"id", storeID,
		"name", managed.store.Name(),
		"event", eventID,
		"active_claims", len(managed.claims))

	return nil
}

// GetDataStore retrieves a store for use
// Returns ErrDataStoreNotClaimed if no events have claimed the store
func (dsm *DataStoreManager) GetDataStore(storeID DataStoreID) (DataStore, error) {
	dsm.mu.RLock()
	defer dsm.mu.RUnlock()

	managed, exists := dsm.stores[storeID]
	if !exists {
		return nil, errfmt.WrapError(fmt.Errorf("%w: %d", ErrDataStoreNotRegistered, storeID))
	}
	if len(managed.claims) == 0 {
		return nil, errfmt.WrapError(fmt.Errorf("%w: %s", ErrDataStoreNotClaimed, managed.store.Name()))
	}

	return managed.store, nil
}

// ResetDataStore clears a store's data while keeping it allocated and registered
// Returns ErrDataStoreClaimed if the store has active claims and force is false
func (dsm *DataStoreManager) ResetDataStore(storeID DataStoreID, force bool) error {
	dsm.mu.RLock()
	managed, exists := dsm.stores[storeID]
	if !exists {
		dsm.mu.RUnlock()
		return errfmt.WrapError(fmt.Errorf("%w: %d", ErrDataStoreNotRegistered, storeID))
	}

	store := managed.store
	activeClaims := len(managed.claims)
	storeName := store.Name()
	resetTimeout := dsm.resetTimeout
	claimedBy := slices.Collect(maps.Keys(managed.claims))
	dsm.mu.RUnlock()

	if activeClaims > 0 {
		if !force {
			return errfmt.WrapError(fmt.Errorf("%w: cannot reset %s (%d event(s), use force=true)", ErrDataStoreClaimed, storeName, activeClaims))
		}

		logger.Debugw("force resetting datastore with active claims",
			"id", storeID,
			"name", storeName,
			"active_claims", activeClaims,
			"claimed_by", claimedBy)
	}

	// Execute Reset without holding manager locks (store may use internal locking)
	err := executeWithTimeout(storeName, "reset", resetTimeout, store.Reset)
	if err != nil {
		return errfmt.WrapError(err)
	}

	logger.Debugw("datastore was reset",
		"id", storeID,
		"name", storeName,
		"forced", force)

	return nil
}

// ResetAllDataStores resets all registered stores
// If force=false, skips claimed stores and returns aggregated errors
// If force=true, resets all stores including claimed ones
func (dsm *DataStoreManager) ResetAllDataStores(force bool) error {
	type storeToReset struct {
		store     DataStore
		claimedBy []events.ID
	}

	dsm.mu.RLock()
	storesToReset := make([]storeToReset, 0, len(dsm.stores))
	resetTimeout := dsm.resetTimeout

	for _, managed := range dsm.stores {
		storesToReset = append(storesToReset, storeToReset{
			store:     managed.store,
			claimedBy: slices.Collect(maps.Keys(managed.claims)),
		})
	}
	dsm.mu.RUnlock()

	// Execute Reset on all stores without holding manager locks (stores may use internal locking)
	var errs []error

	for i := range storesToReset {
		store := storesToReset[i].store
		claimedBy := storesToReset[i].claimedBy

		if len(claimedBy) > 0 {
			if !force {
				errs = append(errs, fmt.Errorf("%w: %s (%v)", ErrDataStoreClaimed, store.Name(), claimedBy))
				continue
			}

			logger.Debugw("force resetting datastore with active claims",
				"id", store.ID(),
				"name", store.Name(),
				"claimed_by", claimedBy)
		}

		err := executeWithTimeout(store.Name(), "reset", resetTimeout, store.Reset)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		logger.Debugw("datastore was reset",
			"id", store.ID(),
			"name", store.Name(),
			"forced", force)
	}

	if len(errs) > 0 {
		return errfmt.WrapError(errors.Join(errs...))
	}

	return nil
}

// UnregisterDataStore removes a store from the manager and shuts it down
// Returns ErrDataStoreClaimed if the store has active claims and force is false
// Returns error if store was unregistered or re-registered during shutdown
func (dsm *DataStoreManager) UnregisterDataStore(storeID DataStoreID, force bool) error {
	dsm.mu.RLock()
	managed, exists := dsm.stores[storeID]
	if !exists {
		dsm.mu.RUnlock()
		return errfmt.WrapError(fmt.Errorf("%w: %d", ErrDataStoreNotRegistered, storeID))
	}

	store := managed.store
	activeClaims := len(managed.claims)
	storeName := store.Name()
	shutdownTimeout := dsm.shutdownTimeout
	claimedBy := slices.Collect(maps.Keys(managed.claims))
	dsm.mu.RUnlock()

	if activeClaims > 0 {
		if !force {
			return errfmt.WrapError(fmt.Errorf("%w: cannot unregister %s (%d event(s), use force=true)", ErrDataStoreClaimed, storeName, activeClaims))
		}

		logger.Debugw("force unregistering datastore with active claims",
			"id", storeID,
			"name", storeName,
			"active_claims", activeClaims,
			"claimed_by", claimedBy)
	}

	// Execute Shutdown without holding manager locks (store may use internal locking)
	err := executeWithTimeout(storeName, "shutdown", shutdownTimeout, store.Shutdown)
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Remove from map
	dsm.mu.Lock()
	defer dsm.mu.Unlock()

	// Re-check store still exists and is the same instance before deleting
	managedAfter, exists := dsm.stores[storeID]
	if !exists {
		return errfmt.WrapError(fmt.Errorf("%w: %s during shutdown", ErrDataStoreUnregisteredDuringOperation, storeName))
	}
	if managedAfter != managed {
		return errfmt.WrapError(fmt.Errorf("%w: %s during shutdown", ErrDataStoreReRegistered, storeName))
	}

	delete(dsm.stores, storeID)

	logger.Debugw("datastore was unregistered",
		"id", storeID,
		"name", storeName,
		"forced", force)

	return nil
}

// UnregisterAllDataStores removes all stores from the manager and shuts them down
// If force=false, skips claimed stores and returns aggregated errors
// If force=true, unregisters all stores including claimed ones
// May return errors for stores unregistered or re-registered during operation
func (dsm *DataStoreManager) UnregisterAllDataStores(force bool) error {
	type storeToUnregister struct {
		store     DataStore
		claimedBy []events.ID
	}

	dsm.mu.RLock()
	storesToUnregister := make([]storeToUnregister, 0, len(dsm.stores))
	shutdownTimeout := dsm.shutdownTimeout

	for _, managed := range dsm.stores {
		storesToUnregister = append(storesToUnregister, storeToUnregister{
			store:     managed.store,
			claimedBy: slices.Collect(maps.Keys(managed.claims)),
		})
	}
	dsm.mu.RUnlock()

	// Execute Shutdown on all stores without holding manager locks (stores may use internal locking)
	var errs []error
	successfulShutdowns := make([]DataStore, 0, len(storesToUnregister))

	for i := range storesToUnregister {
		store := storesToUnregister[i].store
		claimedBy := storesToUnregister[i].claimedBy

		if len(claimedBy) > 0 {
			if !force {
				errs = append(errs, fmt.Errorf("%w: %s (%v)", ErrDataStoreClaimed, store.Name(), claimedBy))
				continue
			}

			logger.Debugw("force unregistering datastore with active claims",
				"id", store.ID(),
				"name", store.Name(),
				"claimed_by", claimedBy)
		}

		err := executeWithTimeout(store.Name(), "shutdown", shutdownTimeout, store.Shutdown)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		successfulShutdowns = append(successfulShutdowns, store)

		logger.Debugw("datastore was unregistered",
			"id", store.ID(),
			"name", store.Name(),
			"forced", force)
	}

	// Remove successfully shut down stores from map (with verification)
	if len(successfulShutdowns) > 0 {
		dsm.mu.Lock()
		for _, store := range successfulShutdowns {
			managedAfter, exists := dsm.stores[store.ID()]
			if !exists {
				errs = append(errs, fmt.Errorf("%w: %s during shutdown", ErrDataStoreUnregisteredDuringOperation, store.Name()))
				continue
			}

			if managedAfter.store != store {
				errs = append(errs, fmt.Errorf("%w: %s during shutdown", ErrDataStoreReRegistered, store.Name()))
				continue
			}

			delete(dsm.stores, store.ID())
		}
		dsm.mu.Unlock()
	}

	if len(errs) > 0 {
		return errfmt.WrapError(errors.Join(errs...))
	}

	return nil
}

//
// DataStoreManager Debugging
//

// DataStoreStatus contains status information about a store
type DataStoreStatus struct {
	ID        DataStoreID
	Name      string
	Len       int // Number of elements in the store (0 if not initialized)
	ClaimedBy []events.ID
}

// String returns a string representation of DataStoreStatus
func (s *DataStoreStatus) String() string {
	return fmt.Sprintf("DataStoreStatus{ID: %d, Name: %s, Len: %d, ClaimedBy: %v}",
		s.ID, s.Name, s.Len, s.ClaimedBy)
}

// GetDataStoreStatus returns detailed status of a store
func (dsm *DataStoreManager) GetDataStoreStatus(storeID DataStoreID) (*DataStoreStatus, error) {
	dsm.mu.RLock()
	defer dsm.mu.RUnlock()

	managed, exists := dsm.stores[storeID]
	if !exists {
		return nil, errfmt.WrapError(fmt.Errorf("%w: %d", ErrDataStoreNotRegistered, storeID))
	}

	return &DataStoreStatus{
		ID:        storeID,
		Name:      managed.store.Name(),
		Len:       managed.store.Len(),
		ClaimedBy: slices.Collect(maps.Keys(managed.claims)),
	}, nil
}

// GetAllDataStoreStatuses returns status for all registered stores
func (dsm *DataStoreManager) GetAllDataStoreStatuses() []*DataStoreStatus {
	dsm.mu.RLock()
	defer dsm.mu.RUnlock()

	statuses := make([]*DataStoreStatus, 0, len(dsm.stores))
	for id, managed := range dsm.stores {
		statuses = append(statuses, &DataStoreStatus{
			ID:        id,
			Name:      managed.store.Name(),
			Len:       managed.store.Len(),
			ClaimedBy: slices.Collect(maps.Keys(managed.claims)),
		})
	}

	return statuses
}

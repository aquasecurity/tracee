package symbol

import (
	"time"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

// DataStore interface implementation

// Name returns the name of this datastore
func (kst *KernelSymbolTable) Name() string {
	return datastores.Symbol
}

// GetHealth returns the current health status of the datastore
func (kst *KernelSymbolTable) GetHealth() *datastores.HealthInfo {
	// Try to acquire lock with retries to distinguish between busy (healthy) and deadlocked (unhealthy)
	const maxAttempts = 10
	const retryDelay = 10 * time.Millisecond // Total max wait: 100ms

	for attempt := range maxAttempts {
		if !kst.symbols.mu.TryRLock() {
			// Failed to acquire lock, retry if not last attempt
			if attempt < maxAttempts-1 {
				time.Sleep(retryDelay)
			}
			continue
		}

		// Verify symbol table is loaded
		symbolCount := len(kst.symbols.sortedSymbols)
		if symbolCount == 0 {
			kst.symbols.mu.RUnlock()
			return &datastores.HealthInfo{
				Status:    datastores.HealthUnhealthy,
				Message:   "symbol table is empty - may not be loaded",
				LastCheck: time.Now(),
			}
		}

		kst.symbols.mu.RUnlock()
		return &datastores.HealthInfo{
			Status:    datastores.HealthHealthy,
			Message:   "",
			LastCheck: time.Now(),
		}
	}

	// Failed to acquire lock after multiple attempts
	return &datastores.HealthInfo{
		Status:    datastores.HealthUnhealthy,
		Message:   "unable to acquire lock after multiple attempts - possible deadlock or severe contention",
		LastCheck: time.Now(),
	}
}

// GetMetrics returns operational metrics for the datastore
func (kst *KernelSymbolTable) GetMetrics() *datastores.DataStoreMetrics {
	kst.symbols.mu.RLock()
	itemCount := int64(len(kst.symbols.sortedSymbols))
	kst.symbols.mu.RUnlock()

	lastAccessNano := kst.lastAccessNano.Load()

	return &datastores.DataStoreMetrics{
		ItemCount:    itemCount,
		SuccessCount: 0, // TODO: Track in Phase 2
		ErrorCount:   0, // TODO: Track in Phase 2
		CacheHits:    0, // N/A for symbol table
		CacheMisses:  0, // N/A for symbol table
		LastAccess:   time.Unix(0, lastAccessNano),
	}
}

// KernelSymbolStore interface implementation

// ResolveSymbolByAddress resolves a kernel address to symbol information
// Returns all symbols at the given address (multiple if aliases exist)
func (kst *KernelSymbolTable) ResolveSymbolByAddress(addr uint64) ([]*datastores.SymbolInfo, error) {
	kst.lastAccessNano.Store(time.Now().UnixNano())

	symbols, err := kst.GetSymbolByAddr(addr)
	if err != nil {
		return nil, err
	}

	if len(symbols) == 0 {
		return nil, datastores.ErrNotFound
	}

	// Convert all symbols
	result := make([]*datastores.SymbolInfo, 0, len(symbols))
	for _, sym := range symbols {
		result = append(result, &datastores.SymbolInfo{
			Name:    sym.Name,
			Address: sym.Address,
			Module:  sym.Owner,
		})
	}

	return result, nil
}

// GetSymbolAddress returns the address of a named symbol
// If multiple symbols exist with the same name (in different modules),
// returns the address of the first one found.
// Returns ErrNotFound if the symbol is not found.
func (kst *KernelSymbolTable) GetSymbolAddress(name string) (uint64, error) {
	kst.lastAccessNano.Store(time.Now().UnixNano())

	symbols, err := kst.GetSymbolByName(name)
	if err != nil {
		return 0, err
	}

	if len(symbols) == 0 {
		return 0, datastores.ErrNotFound
	}

	// Return the first symbol's address
	return symbols[0].Address, nil
}

// ResolveSymbolsBatch resolves multiple addresses to symbols in one call
func (kst *KernelSymbolTable) ResolveSymbolsBatch(addrs []uint64) (map[uint64][]*datastores.SymbolInfo, error) {
	kst.lastAccessNano.Store(time.Now().UnixNano())

	results := make(map[uint64][]*datastores.SymbolInfo, len(addrs))

	for _, addr := range addrs {
		symbols, err := kst.GetSymbolByAddr(addr)
		if err != nil || len(symbols) == 0 {
			// Skip addresses that cannot be resolved
			continue
		}

		// Convert all symbols at this address
		symbolInfos := make([]*datastores.SymbolInfo, 0, len(symbols))
		for _, sym := range symbols {
			symbolInfos = append(symbolInfos, &datastores.SymbolInfo{
				Name:    sym.Name,
				Address: sym.Address,
				Module:  sym.Owner,
			})
		}
		results[addr] = symbolInfos
	}

	return results, nil
}

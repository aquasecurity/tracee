package symbol

import (
	"time"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

// DataStore interface implementation

// Name returns the name of this datastore
func (kst *KernelSymbolTable) Name() string {
	return "symbol"
}

// GetHealth returns the current health status of the datastore
func (kst *KernelSymbolTable) GetHealth() *datastores.HealthInfo {
	// Verify symbol table is loaded
	kst.symbols.mu.RLock()
	symbolCount := len(kst.symbols.sortedSymbols)
	kst.symbols.mu.RUnlock()

	if symbolCount == 0 {
		return &datastores.HealthInfo{
			Status:    datastores.HealthUnhealthy,
			Message:   "symbol table is empty - may not be loaded",
			LastCheck: time.Now(),
		}
	}

	// Try to acquire read lock with timeout to detect deadlocks
	lockAcquired := make(chan struct{})
	go func() {
		kst.symbols.mu.RLock()
		_ = len(kst.symbols.sortedSymbols) // Read data to avoid empty critical section
		kst.symbols.mu.RUnlock()
		close(lockAcquired)
	}()

	select {
	case <-lockAcquired:
		return &datastores.HealthInfo{
			Status:    datastores.HealthHealthy,
			Message:   "",
			LastCheck: time.Now(),
		}
	case <-time.After(100 * time.Millisecond):
		return &datastores.HealthInfo{
			Status:    datastores.HealthUnhealthy,
			Message:   "lock acquisition timeout - possible deadlock",
			LastCheck: time.Now(),
		}
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

package utils

import (
	"errors"
	"sort"
	"sync"
)

// The Symbol interface defines what is needed from a symbol implementation in
// order to facilitate the lookup functionalities provided by SymbolTable.
// Implementations of Symbol can hold various types of information relevant to
// the type of symbol they represent.
type Symbol[T any] interface {
	// Name returns the symbol's name
	Name() string
	// Address returns the base address of the symbol
	Address() uint64
	// Contains returns whether a given address belongs to the symbol's
	// address range, which is defined by the symbol's implementation
	Contains(address uint64) bool
	Cloner[T]
}

// SymbolTable is used to hold information about symbols (mapping from symbolic
// names used in code to their address) in a certain executable.
// It can be used to hold symbols from an ELF binary, or symbols of the entire
// kernel and its modules.
// It provides functions to lookup symbols by address and name.
type SymbolTable[T Symbol[T]] struct {
	mu sync.RWMutex
	// All symbols sorted by their address in descending order,
	// for quick binary searches by address.
	sortedSymbols []*T
	// If lazyNameLookup is true, the symbolsByName map
	// will be populated only when a failed lookup occurs.
	symbolsByName  map[string][]*T
	lazyNameLookup bool
}

var ErrSymbolNotFound = errors.New("symbol not found")

// Creates a new SymbolTable. If lazyNameLookup is true, the mapping from
// name to symbol will be populated only when a failed lookup occurs.
// This reduces memory footprint at the cost of the time it takes to lookup
// a symbol name for the first time.
func NewSymbolTable[T Symbol[T]](lazyNameLookup bool) *SymbolTable[T] {
	return &SymbolTable[T]{
		sortedSymbols:  make([]*T, 0),
		symbolsByName:  make(map[string][]*T),
		lazyNameLookup: lazyNameLookup,
	}
}

// Adds a slice of symbols to the symbol table.
func (st *SymbolTable[T]) AddSymbols(symbols []*T) {
	st.mu.Lock()
	defer st.mu.Unlock()

	// Add the new symbols to the sorted slice (which now becomes unsorted).
	// Allocate the slice with the needed capacity to avoid overallocation.
	oldSymbols := st.sortedSymbols
	newLen := len(oldSymbols) + len(symbols)
	st.sortedSymbols = make([]*T, 0, newLen)
	st.sortedSymbols = append(st.sortedSymbols, oldSymbols...)
	st.sortedSymbols = append(st.sortedSymbols, symbols...)

	// If lazyNameLookup is false, we update the name to symbol mapping for
	// each new symbol
	if !st.lazyNameLookup {
		for _, symbol := range symbols {
			name := (*symbol).Name()
			if symbols, found := st.symbolsByName[name]; found {
				st.symbolsByName[name] = append(symbols, symbol)
			} else {
				st.symbolsByName[name] = []*T{symbol}
			}
		}
	}

	// Sort the symbols slice by address in descending order
	sort.Slice(st.sortedSymbols,
		func(i, j int) bool {
			return (*st.sortedSymbols[i]).Address() > (*st.sortedSymbols[j]).Address()
		})
}

// Lookup a symbol in the table by its name.
// Because there may be multiple symbols with the same name, a slice of all
// matching symbols is returned.
func (st *SymbolTable[T]) LookupByName(name string) ([]*T, error) {
	st.mu.RLock()
	// We call RUnlock manually and not using defer because we may need to upgrade to a write lock later

	// Lookup the name in the name to symbol mapping
	if symbols, found := st.symbolsByName[name]; found {
		st.mu.RUnlock()
		return symbols, nil
	}

	// Lazy name lookup is disabled, the lookup failed
	if !st.lazyNameLookup {
		st.mu.RUnlock()
		return nil, ErrSymbolNotFound
	}

	// Lazy name lookup is enabled, perform a linear search to find the requested name
	symbols := []*T{}
	for _, symbol := range st.sortedSymbols {
		if (*symbol).Name() == name {
			symbols = append(symbols, symbol)
		}
	}

	if len(symbols) > 0 {
		// We found symbols with this name, update the mapping
		st.mu.RUnlock()
		st.mu.Lock()
		defer st.mu.Unlock()
		st.symbolsByName[name] = symbols
		return symbols, nil
	}

	st.mu.RUnlock()
	return nil, ErrSymbolNotFound
}

// Lookup a symbol in the table by its exact address.
// Because there may be multiple symbols at the same address, a slice of all
// matching symbols is returned.
func (st *SymbolTable[T]) LookupByAddressExact(address uint64) ([]*T, error) {
	st.mu.RLock()
	defer st.mu.RUnlock()

	// Find the first symbol at an address smaller than or equal to the requested address
	idx := sort.Search(len(st.sortedSymbols),
		func(i int) bool {
			return address >= (*st.sortedSymbols[i]).Address()
		})

	// Not found or not exact match
	if idx == len(st.sortedSymbols) || (*st.sortedSymbols[idx]).Address() != address {
		return nil, ErrSymbolNotFound
	}

	// The search result is the first symbol with the requested address,
	// find any additional symbols with the same address.
	syms := []*T{st.sortedSymbols[idx]}
	for i := idx + 1; i < len(st.sortedSymbols); i++ {
		if (*st.sortedSymbols[i]).Address() != address {
			break
		}
		syms = append(syms, st.sortedSymbols[i])
	}

	return syms, nil
}

// Find the symbol which contains the given address.
// If multiple symbols at different addresses contain the requested address,
// the symbol with the highest address will be returned.
// If multiple symbols at the same address contain the requested address,
// one of them will be returned, but there is no guarantee which one.
// This function assumes that symbols don't overlap in a way that a symbol with
// a smaller address contains the requested address while a symbol with a larger
// address (but still smaller that requested) doesn't contain it.
// For example, the following situation is assumed to be impossible:
//
//	        Requested Address
//	                 |
//	                 |
//	 +---------------+--+
//	 |Symbol 1       |  |
//	 +---------------+--+
//	    +--------+   |
//	    |Symbol 2|   |
//	    +--------+   v
//	<---------------------->
//
// Smaller            Larger
// Address            Address
//
// If the above situation happens, no symbol will be returned.
func (st *SymbolTable[T]) LookupByAddressContains(address uint64) (*T, error) {
	st.mu.RLock()
	defer st.mu.RUnlock()

	// Find the first symbol at an address smaller than or equal to the requested address
	idx := sort.Search(len(st.sortedSymbols),
		func(i int) bool {
			return address >= (*st.sortedSymbols[i]).Address()
		})

	// Not found or the symbol doesn't contain this address
	if idx == len(st.sortedSymbols) || !(*st.sortedSymbols[idx]).Contains(address) {
		return nil, ErrSymbolNotFound
	}

	return st.sortedSymbols[idx], nil
}

func (st *SymbolTable[T]) ForEachSymbol(callback func(symbol *T)) {
	st.mu.RLock()
	defer st.mu.RUnlock()

	for i := range len(st.sortedSymbols) {
		sym := (*st.sortedSymbols[i]).Clone()
		callback(&sym)
	}
}

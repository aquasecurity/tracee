package events

import (
	"sync/atomic"
)

type KSymbol struct {
	symbol   string
	required *atomic.Bool // tracee should cancel the event if the symbol is missing
}

// NewKSymbol creates a new KSymbolDependency with default values.
func NewKSymbol(symbol string, required bool) *KSymbol {
	r := &atomic.Bool{}

	r.Store(required)

	return &KSymbol{
		symbol:   symbol,
		required: r,
	}
}

// GetSymbol returns a copy of the symbol name (thread-safe).
func (k *KSymbol) GetSymbol() string {
	return k.symbol
}

// SetSymbol does not make sense for KSymbolDependency.

// IsRequired returns true if the dependency is required (thread-safe).
func (k *KSymbol) IsRequired() bool {
	return k.required.Load()
}

// SetRequired sets the dependency as required (thread-safe).
func (k *KSymbol) SetRequired() {
	k.required.Store(true)
}

// SetNotRequired sets the dependency as not required (thread-safe).
func (k *KSymbol) SetNotRequired() {
	k.required.Store(false)
}

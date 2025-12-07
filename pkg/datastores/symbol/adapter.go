package symbol

import (
	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

// Adapter wraps access to kernel symbols which may be hot-reloaded at runtime.
// It always fetches the current symbol table via the provided function.
type Adapter struct {
	getSymbols func() *KernelSymbolTable
}

// NewAdapter creates an adapter that delegates to a function
// that returns the current kernel symbol table
func NewAdapter(getSymbols func() *KernelSymbolTable) datastores.KernelSymbolStore {
	return &Adapter{
		getSymbols: getSymbols,
	}
}

// All methods delegate to the current kernel symbol table

func (a *Adapter) Name() string {
	return datastores.Symbol
}

func (a *Adapter) GetHealth() *datastores.HealthInfo {
	return a.getSymbols().GetHealth()
}

func (a *Adapter) GetMetrics() *datastores.DataStoreMetrics {
	return a.getSymbols().GetMetrics()
}

func (a *Adapter) ResolveSymbolByAddress(addr uint64) ([]*datastores.SymbolInfo, error) {
	return a.getSymbols().ResolveSymbolByAddress(addr)
}

func (a *Adapter) GetSymbolAddress(name string) (uint64, error) {
	return a.getSymbols().GetSymbolAddress(name)
}

func (a *Adapter) ResolveSymbolsBatch(addrs []uint64) (map[uint64][]*datastores.SymbolInfo, error) {
	return a.getSymbols().ResolveSymbolsBatch(addrs)
}

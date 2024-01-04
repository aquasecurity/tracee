package ksyms

import (
	"sync"

	"github.com/aquasecurity/libbpfgo/helpers"
)

type safeKsymbolTable struct {
	helpers.KernelSymbolTable
	l *sync.Mutex
}

// NewSafeKsymbolTable returns a safe wrapper for implementations of the KernelSymbolTable interface.
// The wrapper is needed because provided implementations do not guarentee thread-safety.
func NewSafeKsymbolTable() (*safeKsymbolTable, error) {
	table, err := helpers.NewLazyKernelSymbolsMap()
	if err != nil {
		return nil, err
	}

	return &safeKsymbolTable{
		table, new(sync.Mutex),
	}, nil
}

func (t *safeKsymbolTable) TextSegmentContains(addr uint64) (bool, error) {
	t.l.Lock()
	defer t.l.Unlock()
	return t.KernelSymbolTable.TextSegmentContains(addr)
}

func (t *safeKsymbolTable) GetSymbolByName(owner string, name string) (*helpers.KernelSymbol, error) {
	t.l.Lock()
	defer t.l.Unlock()
	return t.KernelSymbolTable.GetSymbolByName(owner, name)
}

func (t *safeKsymbolTable) GetSymbolByAddr(addr uint64) (*helpers.KernelSymbol, error) {
	t.l.Lock()
	defer t.l.Unlock()
	return t.KernelSymbolTable.GetSymbolByAddr(addr)
}

func (t *safeKsymbolTable) Refresh() error {
	t.l.Lock()
	defer t.l.Unlock()
	return t.KernelSymbolTable.Refresh()
}

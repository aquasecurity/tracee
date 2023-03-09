package ebpf

import (
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
)

var maxKsymNameLen = 64 // Most match the constant in the bpf code
var globalSymbolOwner = "system"

func LoadKallsymsValues(ksymsTable helpers.KernelSymbolTable, ksymbols []string) map[string]*helpers.KernelSymbol {
	kallsymsMap := make(map[string]*helpers.KernelSymbol)
	for _, name := range ksymbols {
		symbol, err := ksymsTable.GetSymbolByName(globalSymbolOwner, name)
		if err == nil {
			kallsymsMap[name] = symbol
		}
	}
	return kallsymsMap
}

func SendKsymbolsToMap(bpfKsymsMap *libbpfgo.BPFMap, ksymbols map[string]*helpers.KernelSymbol) error {
	for ksymName, value := range ksymbols {
		key := make([]byte, maxKsymNameLen)
		copy(key, ksymName)
		address := value.Address
		err := bpfKsymsMap.Update(unsafe.Pointer(&key[0]), unsafe.Pointer(&address))
		if err != nil {
			return errfmt.WrapError(err)
		}
	}
	return nil
}

// ValidateKsymbolsTable checks if the addresses in the table are valid by
// checking a specific symbol address. The reason for the addresses to be
// invalid is if the capabilities required to read the kallsyms file are not
// given. The chosen symbol used here is "security_file_open" because it is a
// must-have symbol for tracee to run.
func ValidateKsymbolsTable(ksyms helpers.KernelSymbolTable) bool {

	sym, err := ksyms.GetSymbolByName(globalSymbolOwner, "security_file_open")
	if err != nil || sym.Address == 0 {
		return false
	}

	return true
}

func (t *Tracee) NewKernelSymbols() error {
	var kernelSymbols helpers.KernelSymbolTable
	var err error

	kernelSymbols, err = helpers.NewLazyKernelSymbolsMap()
	if err != nil {
		return errfmt.WrapError(err)
	}

	if !ValidateKsymbolsTable(kernelSymbols) {
		// debug.PrintStack()
		return errfmt.Errorf("invalid ksymbol table")
	}
	t.kernelSymbols = kernelSymbols

	return nil
}

func (t *Tracee) UpdateKernelSymbols() error {
	return t.kernelSymbols.Refresh()
}

func (t *Tracee) UpdateBPFKsymbolsMap() error {
	var err error
	var bpfKsymsMap *libbpfgo.BPFMap

	bpfKsymsMap, err = t.bpfModule.GetMap("ksymbols_map")
	if err != nil {
		return errfmt.WrapError(err)
	}

	// get required symbols by chosen events
	var reqKsyms []string

	for id := range t.events {
		event := events.Definitions.Get(id)
		if event.Dependencies.KSymbols != nil {
			for _, symDependency := range *event.Dependencies.KSymbols {
				reqKsyms = append(reqKsyms, symDependency.Symbol)
			}
		}
	}
	kallsymsValues := LoadKallsymsValues(t.kernelSymbols, reqKsyms)

	return SendKsymbolsToMap(bpfKsymsMap, kallsymsValues)
}

func (t *Tracee) UpdateKallsyms() error {
	err := t.UpdateKernelSymbols()
	if err != nil {
		return errfmt.WrapError(err)
	}

	return t.UpdateBPFKsymbolsMap()
}

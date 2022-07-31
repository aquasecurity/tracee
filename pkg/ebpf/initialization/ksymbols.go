package initialization

import (
	"github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"
	"unsafe"
)

var maxKsymNameLen = 64 // Most match the constant in the bpf code
var globalSymbolOwner = "system"

func LoadKallsymsValues(ksymsTable *helpers.KernelSymbolTable, ksymbols []string) map[string]*helpers.KernelSymbol {
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
			return err
		}
	}
	return nil
}

// ValidateKsymbolsTable check if the addresses in the table are valid by checking a specific symbol address.
// The reason for the addresses to be invalid is if the capabilities required to read the kallsyms file are not given.
// The chosen symbol used here is "security_file_open" because it is a must-have symbol for tracee to run.
func ValidateKsymbolsTable(ksyms *helpers.KernelSymbolTable) bool {
	if sym, err := ksyms.GetSymbolByName(globalSymbolOwner, "security_file_open"); err != nil || sym.Address == 0 {
		return false
	}
	return true
}

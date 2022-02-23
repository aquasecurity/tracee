package initialization

import "github.com/aquasecurity/libbpfgo/helpers"

var globalSymbolOwner = "system"

// ValidateKsymbolsTable check if the addresses in the table are valid by checking a specific symbol address.
// The reason for the addresses to be invalid is if the capabilities required to read the kallsyms file are not given.
// The chosen symbol used here is "current_task" because it is used by all supported kernel versions and shouldn't be 0.
func ValidateKsymbolsTable(ksyms *helpers.KernelSymbolTable) bool {
	if sym, err := ksyms.GetSymbolByName(globalSymbolOwner, "current_task"); err != nil || sym.Address == 0 {
		return false
	}
	return true
}

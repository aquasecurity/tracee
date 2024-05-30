package utils

import (
	"debug/elf"
	"errors"
	"fmt"

	"github.com/aquasecurity/tracee/pkg/logger"
)

// SymbolToOffset attempts to resolve a 'symbol' name in the binary found at
// 'path' to an offset. The offset can be used for attaching a u(ret)probe
func SymbolToOffset(path, symbol string) (uint32, error) {
	f, err := elf.Open(path)
	if err != nil {
		return 0, fmt.Errorf("could not open elf file to resolve symbol offset: %w", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			logger.Warnw("error closing file", "path", path, "error", err)
		}
	}()

	regularSymbols, regularSymbolsErr := f.Symbols()
	dynamicSymbols, dynamicSymbolsErr := f.DynamicSymbols()

	// Only if we failed getting both regular and dynamic symbols - then we abort.
	if regularSymbolsErr != nil && dynamicSymbolsErr != nil {
		return 0, fmt.Errorf("could not open regular or dynamic symbol sections to resolve symbol offset: %w %s", regularSymbolsErr, dynamicSymbolsErr)
	}

	// Concatenating into a single list.
	// The list can have duplications, but we will find the first occurrence which is sufficient.
	syms := append(regularSymbols, dynamicSymbols...)

	sectionsToSearchForSymbol := []*elf.Section{}

	for i := range f.Sections {
		if f.Sections[i].Flags == elf.SHF_ALLOC+elf.SHF_EXECINSTR {
			sectionsToSearchForSymbol = append(sectionsToSearchForSymbol, f.Sections[i])
		}
	}

	var executableSection *elf.Section

	for j := range syms {
		if syms[j].Name == symbol {
			// Find what section the symbol is in by checking the executable section's
			// addr space.
			for m := range sectionsToSearchForSymbol {
				if syms[j].Value > sectionsToSearchForSymbol[m].Addr &&
					syms[j].Value < sectionsToSearchForSymbol[m].Addr+sectionsToSearchForSymbol[m].Size {
					executableSection = sectionsToSearchForSymbol[m]
				}
			}

			if executableSection == nil {
				return 0, errors.New("could not find symbol in executable sections of binary")
			}

			return uint32(syms[j].Value - executableSection.Addr + executableSection.Offset), nil
		}
	}

	return 0, fmt.Errorf("symbol %s not found in %s", symbol, path)
}

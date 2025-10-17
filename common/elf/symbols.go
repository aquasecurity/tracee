package elf

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/logger"
)

// WantedSymbol interface for different types of symbols that can be searched for
type WantedSymbol interface {
	Matches(symbolName string) bool
	String() string
}

// PlainSymbolName represents a regular symbol name for exact string matching
type PlainSymbolName string

func (s PlainSymbolName) Matches(symbolName string) bool {
	return string(s) == symbolName
}

func (s PlainSymbolName) String() string {
	return string(s)
}

// NewPlainSymbolName creates a WantedSymbol for exact string matching
func NewPlainSymbolName(name string) WantedSymbol {
	return PlainSymbolName(name)
}

// WantedSymbolsFromStrings converts a map of string symbols to WantedSymbol slice
func WantedSymbolsFromStrings(symbols map[string]struct{}) []WantedSymbol {
	if len(symbols) == 0 {
		return nil
	}

	wanted := make([]WantedSymbol, 0, len(symbols))
	for symbol := range symbols {
		wanted = append(wanted, PlainSymbolName(symbol))
	}
	return wanted
}

type ElfSymbol struct {
	Name        string
	Info, Other byte
	Section     elf.SectionIndex
	Value, Size uint64
}

func (s ElfSymbol) IsImported() bool {
	return elf.ST_BIND(s.Info) == elf.STB_GLOBAL && s.Section == elf.SHN_UNDEF
}

func (ea *ElfAnalyzer) GetSymbolOffset(symbolName string) (uint64, error) {
	symbol, err := ea.GetSymbol(symbolName)
	if err != nil {
		return 0, err
	}

	return ea.getSymbolOffset(symbol)
}

func (ea *ElfAnalyzer) getSymbolOffset(symbol *ElfSymbol) (uint64, error) {
	if symbol.IsImported() {
		return 0, errfmt.Errorf("%s is an imported symbol", symbol.Name)
	}

	if int(symbol.Section) >= len(ea.elf.Sections) {
		return 0, errfmt.Errorf("invalid section %d for symbol %s", symbol.Section, symbol.Name)
	}
	section := ea.elf.Sections[symbol.Section]
	return symbol.Value - section.Addr + section.Offset, nil
}

func (ea *ElfAnalyzer) GetSymbol(symbolName string) (*ElfSymbol, error) {
	symbols, err := ea.getSymbols()
	if err != nil {
		return nil, errfmt.WrapError(err)
	}

	if symbol, ok := symbols[symbolName]; ok {
		return symbol, nil
	}

	return nil, fmt.Errorf("could not find symbol %s: %w", symbolName, ErrSymbolNotFound)
}

func (ea *ElfAnalyzer) getSymbols() (map[string]*ElfSymbol, error) {
	if ea.symbols != nil {
		return ea.symbols, nil
	}

	start := time.Now()

	ea.symbols = make(map[string]*ElfSymbol)

	// Load regular symbols
	if err := ea.loadSymbols(elf.SHT_SYMTAB); err != nil {
		if !errors.Is(err, elf.ErrNoSymbols) {
			return nil, err
		}
	}

	// Load dynamic symbols
	if err := ea.loadSymbols(elf.SHT_DYNSYM); err != nil {
		if !errors.Is(err, elf.ErrNoSymbols) {
			return nil, err
		}
	}

	logger.Debugw("loaded symbols", "path", ea.filePath, "time", time.Since(start))

	return ea.symbols, nil
}

// loadSymbols loads symbols from the specified symbol section type into ea.symbols.
// If this ElfAnalyzer has wanted symbols, only the wanted symbols are loaded.
// This function is based on the implementation in debug/elf, but it doesn't read the entire
// symbol and string table sections into memory, and only saves wanted symbols (if specified).
func (ea *ElfAnalyzer) loadSymbols(typ elf.SectionType) error {
	var is64Bit bool
	var symSize uint64
	switch ea.elf.Class {
	case elf.ELFCLASS64:
		is64Bit = true
		symSize = elf.Sym64Size
	case elf.ELFCLASS32:
		is64Bit = false
		symSize = elf.Sym32Size
	default:
		return fmt.Errorf("invalid ELF class %d", ea.elf.Class)
	}

	// Open symbol table section for reading
	symtabSection := ea.elf.SectionByType(typ)
	if symtabSection == nil {
		return elf.ErrNoSymbols
	}
	if symtabSection.Size%symSize != 0 {
		return errors.New("length of symbol section is not a multiple of symSize")
	}
	symtab := symtabSection.Open()

	// Open linked string table for reading
	if symtabSection.Link <= 0 || symtabSection.Link >= uint32(len(ea.elf.Sections)) {
		return errors.New("section has invalid string table link")
	}
	strtabSection := ea.elf.Sections[symtabSection.Link]
	strtab := strtabSection.Open()

	var wantedNames map[uint32]struct{}
	if ea.wantedSymbolsOnly {
		// Find the names of wanted symbols in the string table.
		// This is meant to optimize access to the string table, such that it
		// follows a sequential order. This access fashion allows us to employ
		// an aggressive memory reclamation scheme.
		var err error
		wantedNames, err = findWantedSymbolNames(
			ea.mmapData[strtabSection.Offset:strtabSection.Offset+strtabSection.Size],
			ea.wantedSymbols)
		if err != nil {
			return err
		}
	}

	// The first symbol table entry is all zeros, skip it
	if _, err := symtab.Seek(int64(symSize), io.SeekStart); err != nil {
		return errors.New("error reading from symbol table section")
	}

	// Read symbols one at a time
	sym := make([]byte, symSize)
	for {
		if n, err := symtab.Read(sym); err != nil || n != len(sym) {
			if errors.Is(err, io.EOF) {
				break
			}
			return errors.New("error reading from symbol table section")
		}

		// Extract symbol name, check if wanted

		stName := ea.elf.ByteOrder.Uint32(sym[0:4])
		if ea.wantedSymbolsOnly {
			if _, ok := wantedNames[stName]; !ok {
				// Not a wanted symbol
				continue
			}
		}
		name, err := getString(strtab, strtabSection.Size, stName)
		if err != nil {
			return err
		}

		// Extract symbol info

		var stInfo byte
		var stOther byte
		var stShndx uint16
		var stValue uint64
		var stSize uint64

		if is64Bit {
			stInfo = sym[4]
			stOther = sym[5]
			stShndx = ea.elf.ByteOrder.Uint16(sym[6:8])
			stValue = ea.elf.ByteOrder.Uint64(sym[8:16])
			stSize = ea.elf.ByteOrder.Uint64(sym[16:24])
		} else {
			stValue = uint64(ea.elf.ByteOrder.Uint32(sym[4:8]))
			stSize = uint64(ea.elf.ByteOrder.Uint32(sym[8:12]))
			stInfo = sym[12]
			stOther = sym[13]
			stShndx = ea.elf.ByteOrder.Uint16(sym[14:16])
		}

		// Add to symbols
		ea.symbols[name] = &ElfSymbol{
			Name:    name,
			Info:    stInfo,
			Other:   stOther,
			Section: elf.SectionIndex(stShndx),
			Value:   stValue,
			Size:    stSize,
		}
	}

	return nil
}

var errStrtabRead = errors.New("error reading from string table section")

// findWantedSymbolNames finds the offsets of strings in the string table
// corresponding to a collection of wanted symbols names.
// The purpose of this function is to turn random access to the string table
// (used for fetching symbol names on demand) into sequential access by
// scanning it from start to finish in one go.
// This allows us to use madvise to free memory that we already processed,
// preventing very large string tables from inflating the tracee process' RSS.
//
// ELF String Table Compression Handling:
// The function handles ELF linker string table optimizations:
//   - Duplicate strings: Reduced to a single copy
//   - Tail strings (suffix sharing): Multiple symbols share storage by referencing
//     different offsets within the same string
//     Example: "bigdog" at offset 0, "dog" references offset 3
//
// Matching Strategy:
//  1. Exact matches: When a wanted symbol exactly matches a string at a null-terminated boundary
//  2. Tail matches: When a wanted symbol (PlainSymbolName only) is a suffix of another string
//  3. Priority: Exact matches are preferred; tail matches are only returned if no exact match exists
//
// The returned map contains string table offsets (keys) of all matched wanted symbols.
//
// Reference: https://docs.oracle.com/cd/E23824_01/html/819-0690/ggdlu.html
func findWantedSymbolNames(strtab []byte, wantedSymbols []WantedSymbol) (map[uint32]struct{}, error) {
	const chunkSize = 4096 * 128 // 512KB

	// Track exact matches
	exactMatches := make(map[uint32]struct{})
	// Track which wanted symbols have exact matches
	hasExactMatch := make(map[string]struct{})
	// Track tail string matches: offset -> wanted symbol name
	tailMatches := make(map[uint32]string)

	currChunk := 0
	currString := 0

	for i, c := range strtab {
		if i >= currChunk+chunkSize {
			// Free previous chunk
			if err := madviseAligned(strtab[currChunk:currChunk+chunkSize], syscall.MADV_DONTNEED); err != nil {
				return nil, fmt.Errorf("madvise failed: %v", err)
			}
			currChunk += chunkSize
		}

		if c == 0 {
			// NULL terminator - process if not empty string and update currString
			if i > currString {
				// Non-empty string - check for exact matches or tail strings
				str := string(strtab[currString:i])

				// Check all wanted symbols - either exact match or tail string
				for _, wantedSymbol := range wantedSymbols {
					wantedStr := wantedSymbol.String()

					// Check for exact match at this offset
					if wantedSymbol.Matches(str) {
						exactMatches[uint32(currString)] = struct{}{}
						hasExactMatch[wantedStr] = struct{}{}
					} else if _, isPlain := wantedSymbol.(PlainSymbolName); isPlain {
						// Check for tail string match (suffix) - only for PlainSymbolName
						// Tail string optimization is an ELF linker feature for plain string names,
						// not applicable to other WantedSymbol types.
						if len(str) > len(wantedStr) && strings.HasSuffix(str, wantedStr) {
							offset := uint32(currString + len(str) - len(wantedStr))
							tailMatches[offset] = wantedStr
						}
					}
				}
			}

			// Update current string position after each null terminator
			currString = i + 1
		}
	}

	// Build final result: exact matches + substring matches for symbols without exact matches
	result := make(map[uint32]struct{}, len(exactMatches))
	for offset := range exactMatches {
		result[offset] = struct{}{}
	}
	for offset, wantedStr := range tailMatches {
		if _, found := hasExactMatch[wantedStr]; !found {
			// No exact match was found for this wanted symbol, include the substring match
			result[offset] = struct{}{}
		}
	}

	return result, nil
}

func madviseAligned(data []byte, advice int) error {
	if len(data) == 0 {
		return nil
	}

	// Align data start to page boundary
	dataStart := uintptr(unsafe.Pointer(&data[0]))
	alignedStart := dataStart &^ uintptr(syscall.Getpagesize()-1)
	alignedLen := len(data) + int(dataStart-alignedStart)

	// Call madvise with the page-aligned range
	_, _, errno := syscall.Syscall(
		syscall.SYS_MADVISE,
		uintptr(alignedStart),
		uintptr(alignedLen),
		uintptr(advice),
	)

	if errno != 0 {
		return errno
	}

	return nil
}

func getString(strtab io.ReadSeeker, strtabSize uint64, offset uint32) (string, error) {
	if uint64(offset) >= strtabSize {
		return "", errStrtabRead
	}

	if _, err := strtab.Seek(int64(offset), io.SeekStart); err != nil {
		return "", errStrtabRead
	}

	// Find string length
	length := 0
	data := make([]byte, 100) // Read 100 bytes at a time for efficiency
outer:
	for {
		n, err := strtab.Read(data)
		if err != nil && !errors.Is(err, io.EOF) {
			return "", errStrtabRead
		}

		for i := range n {
			if data[i] == 0 {
				// NULL-terminator - end of string
				break outer
			}
			length++
		}

		if errors.Is(err, io.EOF) {
			// Last read reached EOF and no NULL-terminator found
			return "", errStrtabRead
		}
	}

	// Read entire string
	stringData := make([]byte, length)
	if _, err := strtab.Seek(int64(offset), io.SeekStart); err != nil {
		return "", errStrtabRead
	}
	if n, err := strtab.Read(stringData); n != length || err != nil {
		return "", errStrtabRead
	}
	return string(stringData), nil
}

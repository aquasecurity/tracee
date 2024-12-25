package environment

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/utils"
)

const (
	// Kernel symbols do not have an associated size, so we define a sensible size
	// limit to prevent unrelated symbols from being returned for an address lookup
	maxSymbolSize = 0x100000

	ownerShift          = 48                           // Number of bits to shift the owner into the upper 16 bits
	addressMask         = (1 << ownerShift) - 1        // Mask to extract the address from the addressAndOwner field
	kernelAddressPrefix = uint64(0xffff) << ownerShift // Precomputed prefix for kernel addresses
)

// KernelSymbol is a friendly representation of a kernel symbol.
type KernelSymbol struct {
	Name    string
	Address uint64
	Owner   string
}

// kernelSymbolInternal is a memory efficient representation of
// a kernel symbol, used internally for storing all symbols.
type kernelSymbolInternal struct {
	name string
	// We save only the low 48 bits of the address, as all (non-percpu) symbols are at 0xffffXXXXXXXXXXXX
	// Owner is a 16-bit index into a slice of seen owners for the symbol table this symbol belongs to.
	// It can only be translated to the owner name if we have the symbol table.
	// To conserve memory, we encode both of them as a single 64-bit integer where the lower 48-bits
	// are the address and the hight 16-bits are the owner index.
	addressAndOwner uint64
}

func newKernelSymbolInternal(name string, address uint64, owner uint16) *kernelSymbolInternal {
	return &kernelSymbolInternal{
		name:            name,
		addressAndOwner: (uint64(owner) << ownerShift) | (address & addressMask),
	}
}

func (ks kernelSymbolInternal) Name() string {
	return ks.name
}

func (ks kernelSymbolInternal) Address() uint64 {
	// Convert truncated address to the real kernel address
	return kernelAddressPrefix | (ks.addressAndOwner & addressMask)
}

func (ks kernelSymbolInternal) owner() uint16 {
	return uint16(ks.addressAndOwner >> ownerShift)
}

func (ks kernelSymbolInternal) Contains(address uint64) bool {
	symbolAddr := ks.Address()
	return symbolAddr <= address && symbolAddr+maxSymbolSize > address
}

func (ks kernelSymbolInternal) Clone() kernelSymbolInternal {
	return kernelSymbolInternal{
		name:            ks.name,
		addressAndOwner: ks.addressAndOwner,
	}
}

type KernelSymbolTable struct {
	symbols *utils.SymbolTable[kernelSymbolInternal]

	// Used for memory efficient representation of symbol owners
	idxToSymbolOwner []string
	symbolOwnerToIdx map[string]uint16
}

// Creates a new KernelSymbolTable that will be populated from a reader.
// If lazyNameLookup is true, the mapping from name to symbol will be populated
// only when a failed lookup occurs. This reduces memory footprint at the cost
// of the time it takes to lookup a symbol name for the first time.
// If requiredDataSymbolsOnly is true, only the data symbols passed in the
// optional requiredDataSymbols argument will be added.
func NewKernelSymbolTableFromReader(reader io.Reader, lazyNameLookup bool, requiredDataSymbolsOnly bool, requiredDataSymbols ...string) (*KernelSymbolTable, error) {
	kst := &KernelSymbolTable{
		symbols:          utils.NewSymbolTable[kernelSymbolInternal](lazyNameLookup),
		idxToSymbolOwner: []string{"system"},
		symbolOwnerToIdx: map[string]uint16{"system": 0},
	}

	if err := kst.update(reader, requiredDataSymbolsOnly, requiredDataSymbols); err != nil {
		return nil, err
	}

	return kst, nil
}

// Creates a new KernelSymbolTable that will be populated from /proc/kallsyms.
// If lazyNameLookup is true, the mapping from name to symbol will be populated
// only when a failed lookup occurs. This reduces memory footprint at the cost
// of the time it takes to lookup a symbol name for the first time.
// If requiredDataSymbolsOnly is true, only the data symbols passed in the
// optional requiredDataSymbols argument will be added.
func NewKernelSymbolTable(lazyNameLookup bool, requiredDataSymbolsOnly bool, requiredDataSymbols ...string) (*KernelSymbolTable, error) {
	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil, errfmt.WrapError(err)
	}
	defer func() {
		_ = file.Close()
	}()

	return NewKernelSymbolTableFromReader(file, lazyNameLookup, requiredDataSymbolsOnly, requiredDataSymbols...)
}

// Read the contents of the given buffer and update the symbol table
func (kst *KernelSymbolTable) update(reader io.Reader, requiredDataSymbolsOnly bool, requiredDataSymbols []string) error {
	// Build set of required data symbols for efficient lookup
	requiredDataSymbolsSet := make(map[string]struct{})
	for _, symbolName := range requiredDataSymbols {
		requiredDataSymbolsSet[symbolName] = struct{}{}
	}

	symbols := []*kernelSymbolInternal{}

	// Make sure we hold the required privileges by checking if we see actual addresses
	seenRealAddress := false

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}

		symbolAddr, err := strconv.ParseUint(fields[0], 16, 64)
		if err != nil {
			continue
		}
		if symbolAddr != 0 {
			seenRealAddress = true
		}

		// All kernel symbols are at 0xffffXXXXXXXXXXXX, except percpu symbols which we ignore
		if !validKernelAddr(symbolAddr) {
			continue
		}

		symbolType := fields[1]
		symbolName := fields[2]

		symbolOwner := "system"
		if len(fields) > 3 {
			symbolOwner = fields[3]
			symbolOwner = strings.TrimPrefix(symbolOwner, "[")
			symbolOwner = strings.TrimSuffix(symbolOwner, "]")
		}

		// This is a data symbol, requiredDataSymbolsOnly is true, and this symbol isn't required
		if requiredDataSymbolsOnly && strings.ContainsAny(symbolType, "DdBbRr") {
			if _, exists := requiredDataSymbolsSet[symbolName]; !exists {
				continue
			}
		}

		// Get index of symbol owner, or add it if it doesn't exist
		ownerIdx := kst.getOrAddSymbolOwner(symbolOwner)

		symbols = append(symbols, newKernelSymbolInternal(symbolName, symbolAddr, ownerIdx))
	}

	// We didn't hold the required privileges
	if len(symbols) > 0 && !seenRealAddress {
		return errfmt.Errorf("insufficient privileges when reading from /proc/kallsyms")
	}

	// Update the symbol table
	kst.symbols.AddSymbols(symbols)

	return nil
}

func (kst *KernelSymbolTable) getOrAddSymbolOwner(ownerStr string) uint16 {
	ownerIdx, found := kst.symbolOwnerToIdx[ownerStr]
	if !found {
		kst.idxToSymbolOwner = append(kst.idxToSymbolOwner, ownerStr)
		ownerIdx = uint16(len(kst.idxToSymbolOwner) - 1)
		kst.symbolOwnerToIdx[ownerStr] = ownerIdx
	}

	return ownerIdx
}

func (kst *KernelSymbolTable) symbolFromInternal(symbol *kernelSymbolInternal) *KernelSymbol {
	return &KernelSymbol{
		Name:    symbol.Name(),
		Address: symbol.Address(),
		Owner:   kst.idxToSymbolOwner[symbol.owner()],
	}
}

// GetSymbolByName returns all the symbols with the given name.
func (kst *KernelSymbolTable) GetSymbolByName(name string) ([]*KernelSymbol, error) {
	symbolsInternal, err := kst.symbols.LookupByName(name)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}

	symbols := make([]*KernelSymbol, 0, len(symbolsInternal))
	for _, symbolInternal := range symbolsInternal {
		symbols = append(symbols, kst.symbolFromInternal(symbolInternal))
	}

	return symbols, nil
}

// GetSymbolByOwnerAndName returns all the symbols with the given owner and name.
func (kst *KernelSymbolTable) GetSymbolByOwnerAndName(owner, name string) ([]*KernelSymbol, error) {
	symbolsInternal, err := kst.symbols.LookupByName(name)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}

	symbols := make([]*KernelSymbol, 0, len(symbolsInternal))
	for _, symbolInternal := range symbolsInternal {
		symbol := kst.symbolFromInternal(symbolInternal)
		// Return only symbols that have the requested owner
		if symbol.Owner == owner {
			symbols = append(symbols, symbol)
		}
	}

	return symbols, nil
}

// GetSymbolByAddr returns all the symbols with the given address.
func (kst *KernelSymbolTable) GetSymbolByAddr(addr uint64) ([]*KernelSymbol, error) {
	symbolsInternal, err := kst.symbols.LookupByAddressExact(addr)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}

	symbols := make([]*KernelSymbol, 0, len(symbolsInternal))
	for _, symbolInternal := range symbolsInternal {
		symbols = append(symbols, kst.symbolFromInternal(symbolInternal))
	}

	return symbols, nil
}

// GetPotentiallyHiddenSymbolByAddr returns all the symbols with the given address,
// or if none are found, a fake symbol with the "hidden" owner.
func (kst *KernelSymbolTable) GetPotentiallyHiddenSymbolByAddr(addr uint64) []*KernelSymbol {
	symbolsInternal, err := kst.symbols.LookupByAddressExact(addr)
	if err != nil || !validKernelAddr(addr) {
		// No symbol found or address not in kernel range, return a fake "hidden" symbol
		return []*KernelSymbol{{
			Address: addr,
			Owner:   "hidden",
		}}
	}

	symbols := make([]*KernelSymbol, 0, len(symbolsInternal))
	for _, symbolInternal := range symbolsInternal {
		symbols = append(symbols, kst.symbolFromInternal(symbolInternal))
	}

	return symbols
}

func (kst *KernelSymbolTable) ForEachSymbol(callback func(*KernelSymbol)) {
	kst.symbols.ForEachSymbol(func(symbol *kernelSymbolInternal) {
		callback(kst.symbolFromInternal(symbol))
	})
}

func validKernelAddr(addr uint64) bool {
	return addr&kernelAddressPrefix == kernelAddressPrefix
}

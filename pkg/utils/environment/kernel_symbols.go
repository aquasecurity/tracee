package environment

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

const (
	kallsymsPath = "/proc/kallsyms"
	chanBuffer   = 112800 // TODO: check if we really need this buffer size
)

type KernelSymbol struct {
	Name    string
	Type    string
	Address uint64
	Owner   string
}
type nameAndOwner struct {
	name  string
	owner string
}
type addrAndOwner struct {
	addr  uint64
	owner string
}

// KernelSymbolTable manages kernel symbols with multiple maps for fast lookup.
type KernelSymbolTable struct {
	symbols       map[string][]*KernelSymbol
	addrs         map[uint64][]*KernelSymbol
	symByName     map[nameAndOwner][]*KernelSymbol
	symByAddr     map[addrAndOwner][]*KernelSymbol
	requiredSyms  map[string]struct{}
	requiredAddrs map[uint64]struct{}
	onlyRequired  bool
	updateLock    sync.Mutex
	updateWg      sync.WaitGroup
}

func symNotFoundErr(v interface{}) error {
	return fmt.Errorf("symbol not found: %v", v)
}

// NewKernelSymbolTable initializes a KernelSymbolTable with optional configuration functions.
func NewKernelSymbolTable(opts ...KSymbTableOption) (*KernelSymbolTable, error) {
	k := &KernelSymbolTable{}
	for _, opt := range opts {
		if err := opt(k); err != nil {
			return nil, err
		}
	}

	// Set onlyRequired to true if there are required symbols or addresses
	k.onlyRequired = k.requiredAddrs != nil || k.requiredSyms != nil

	// Initialize maps if they are nil
	if k.requiredSyms == nil {
		k.requiredSyms = make(map[string]struct{})
	}
	if k.requiredAddrs == nil {
		k.requiredAddrs = make(map[uint64]struct{})
	}

	return k, k.Refresh()
}

// KSymbTableOption defines a function signature for configuration options.
type KSymbTableOption func(k *KernelSymbolTable) error

// WithRequiredSymbols sets the required symbols for the KernelSymbolTable.
func WithRequiredSymbols(reqSyms []string) KSymbTableOption {
	return func(k *KernelSymbolTable) error {
		k.requiredSyms = sliceToValidationMap(reqSyms)
		return nil
	}
}

// WithRequiredAddresses sets the required addresses for the KernelSymbolTable.
func WithRequiredAddresses(reqAddrs []uint64) KSymbTableOption {
	return func(k *KernelSymbolTable) error {
		k.requiredAddrs = sliceToValidationMap(reqAddrs)
		return nil
	}
}

// TextSegmentContains returns true if the given address is in the kernel text segment.
func (k *KernelSymbolTable) TextSegmentContains(addr uint64) (bool, error) {
	k.updateLock.Lock()
	defer k.updateLock.Unlock()

	segStart, segEnd, err := k.getTextSegmentAddresses()
	if err != nil {
		return false, err
	}

	return addr >= segStart && addr < segEnd, nil
}

// GetSymbolByName returns all the symbols with the given name.
func (k *KernelSymbolTable) GetSymbolByName(name string) ([]KernelSymbol, error) {
	k.updateLock.Lock()
	defer k.updateLock.Unlock()

	if err := k.validateOrAddRequiredSym(name); err != nil {
		return nil, err
	}

	symbols, exist := k.symbols[name]
	if !exist {
		return nil, symNotFoundErr(name)
	}

	return copySliceOfPointersToSliceOfStructs(symbols), nil
}

// GetSymbolByAddr returns all the symbols with the given address.
func (k *KernelSymbolTable) GetSymbolByAddr(addr uint64) ([]KernelSymbol, error) {
	k.updateLock.Lock()
	defer k.updateLock.Unlock()

	if err := k.validateOrAddRequiredAddr(addr); err != nil {
		return nil, err
	}

	symbols, exist := k.addrs[addr]
	if !exist {
		return nil, symNotFoundErr(addr)
	}

	return copySliceOfPointersToSliceOfStructs(symbols), nil
}

// GetSymbolByOwnerAndName returns all the symbols with the given owner and name.
func (k *KernelSymbolTable) GetSymbolByOwnerAndName(owner, name string) ([]KernelSymbol, error) {
	k.updateLock.Lock()
	defer k.updateLock.Unlock()

	if err := k.validateOrAddRequiredSym(name); err != nil {
		return nil, err
	}

	symbols, exist := k.symByName[nameAndOwner{name, owner}]
	if !exist {
		return nil, symNotFoundErr(nameAndOwner{name, owner})
	}

	return copySliceOfPointersToSliceOfStructs(symbols), nil
}

// GetSymbolByOwnerAndAddr returns all the symbols with the given owner and address.
func (k *KernelSymbolTable) GetSymbolByOwnerAndAddr(owner string, addr uint64) ([]KernelSymbol, error) {
	k.updateLock.Lock()
	defer k.updateLock.Unlock()

	if err := k.validateOrAddRequiredAddr(addr); err != nil {
		return nil, err
	}

	symbols, exist := k.symByAddr[addrAndOwner{addr, owner}]
	if !exist {
		return nil, symNotFoundErr(addrAndOwner{addr, owner})
	}

	return copySliceOfPointersToSliceOfStructs(symbols), nil
}

// getTextSegmentAddresses gets the start and end addresses of the kernel text segment.
func (k *KernelSymbolTable) getTextSegmentAddresses() (uint64, uint64, error) {
	stext, exist1 := k.symByName[nameAndOwner{"_stext", "system"}]
	etext, exist2 := k.symByName[nameAndOwner{"_etext", "system"}]

	if !exist1 || !exist2 {
		return 0, 0, fmt.Errorf("kernel text segment symbol(s) not found")
	}

	textSegStart := stext[0].Address
	textSegEnd := etext[0].Address

	return textSegStart, textSegEnd, nil
}

// validateOrAddRequiredSym checks if the given symbol is in the required list and adds it if not.
func (k *KernelSymbolTable) validateOrAddRequiredSym(sym string) error {
	return k.validateOrAddRequired(func() bool {
		_, ok := k.requiredSyms[sym]
		return ok
	}, func() {
		k.requiredSyms[sym] = struct{}{}
	})
}

// validateOrAddRequiredAddr checks if the given address is in the required list and adds it if not.
func (k *KernelSymbolTable) validateOrAddRequiredAddr(addr uint64) error {
	return k.validateOrAddRequired(func() bool {
		_, ok := k.requiredAddrs[addr]
		return ok
	}, func() {
		k.requiredAddrs[addr] = struct{}{}
	})
}

// validateOrAddRequired is a common function to check and add required symbols or addresses.
func (k *KernelSymbolTable) validateOrAddRequired(checkRequired func() bool, addRequired func()) error {
	if !k.onlyRequired {
		return nil
	}

	if !checkRequired() {
		addRequired()
		return k.refresh()
	}

	return nil
}

// Refresh is the exported method that acquires the lock and calls the internal refresh method.
func (k *KernelSymbolTable) Refresh() error {
	k.updateLock.Lock()
	defer k.updateLock.Unlock()
	return k.refresh()
}

// refresh refreshes the KernelSymbolTable, reading the symbols from /proc/kallsyms.
func (k *KernelSymbolTable) refresh() error {
	// Re-initialize the maps to include all new symbols.
	k.symbols = make(map[string][]*KernelSymbol)
	k.addrs = make(map[uint64][]*KernelSymbol)
	k.symByName = make(map[nameAndOwner][]*KernelSymbol)
	k.symByAddr = make(map[addrAndOwner][]*KernelSymbol)

	// Open the kallsyms file.
	file, err := os.Open(kallsymsPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
	}()

	// Read the kallsyms file line by line and process each line.
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		sym := parseKallsymsLine(fields)
		if sym == nil {
			continue
		}

		if k.onlyRequired {
			_, symRequired := k.requiredSyms[sym.Name]
			_, addrRequired := k.requiredAddrs[sym.Address]
			if !symRequired && !addrRequired {
				continue
			}
		}

		k.symbols[sym.Name] = append(k.symbols[sym.Name], sym)
		k.addrs[sym.Address] = append(k.addrs[sym.Address], sym)
		k.symByName[nameAndOwner{sym.Name, sym.Owner}] = append(k.symByName[nameAndOwner{sym.Name, sym.Owner}], sym)
		k.symByAddr[addrAndOwner{sym.Address, sym.Owner}] = append(k.symByAddr[addrAndOwner{sym.Address, sym.Owner}], sym)
	}
	err = scanner.Err()

	return err
}

// parseKallsymsLine parses a line from /proc/kallsyms and returns a KernelSymbol.
func parseKallsymsLine(line []string) *KernelSymbol {
	if len(line) < 3 {
		return nil
	}

	symbolAddr, err := strconv.ParseUint(line[0], 16, 64)
	if err != nil {
		return nil
	}

	symbolType := line[1]
	symbolName := line[2]

	symbolOwner := "system"
	if len(line) > 3 {
		line[3] = strings.TrimPrefix(line[3], "[")
		line[3] = strings.TrimSuffix(line[3], "]")
		symbolOwner = line[3]
	}

	return &KernelSymbol{
		Name:    symbolName,
		Type:    symbolType,
		Address: symbolAddr,
		Owner:   symbolOwner,
	}
}

// copySliceOfPointersToSliceOfStructs converts a slice of pointers to a slice of structs.
func copySliceOfPointersToSliceOfStructs(s []*KernelSymbol) []KernelSymbol {
	ret := make([]KernelSymbol, len(s))
	for i, v := range s {
		ret[i] = *v
	}
	return ret
}

// sliceToValidationMap converts a slice to a map for validation purposes.
func sliceToValidationMap[T comparable](items []T) map[T]struct{} {
	res := make(map[T]struct{})
	for _, item := range items {
		res[item] = struct{}{}
	}
	return res
}

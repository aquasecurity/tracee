package environment

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/aquasecurity/tracee/pkg/logger"
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

// Refresh is the exported method that acquires the lock and calls the internal refresh method.
func (k *KernelSymbolTable) Refresh() error {
	k.updateLock.Lock()
	defer k.updateLock.Unlock()
	return k.refresh()
}

// Concurrency logic for updating the maps: faster than a single goroutine that
// updates all maps OR multiple goroutines with fine grained locking (turned out
// to be slower than a single goroutine).
//
// Simple file parsing (no processing) takes ~0.200 seconds on a 4-core machine.
// If buffer is increased to 4MB, it might take ~0.150 seconds. A simple
// mono-threaded implementation that parses + processes the lines takes ~0.700
// seconds. This approach takes ~0.350 seconds (2x speedup).
//
// NOTE: The procfs file reading cannot be paralelized because procfs does not
// implement mmap (if it was, the reading could be done in parallel chunks and
// processed in different goroutines).

// Refresh refreshes the KernelSymbolTable, reading the symbols from /proc/kallsyms.
func (k *KernelSymbolTable) refresh() error {
	// Re-initialize the maps to include all new symbols.
	k.symbols = make(map[string][]*KernelSymbol)
	k.addrs = make(map[uint64][]*KernelSymbol)
	k.symByName = make(map[nameAndOwner][]*KernelSymbol)
	k.symByAddr = make(map[addrAndOwner][]*KernelSymbol)

	// Create the channels for the map update goroutines.
	symbolChan := make(chan *KernelSymbol, chanBuffer)
	addrChan := make(chan *KernelSymbol, chanBuffer)
	symByNameChan := make(chan *KernelSymbol, chanBuffer)
	symByAddrChan := make(chan *KernelSymbol, chanBuffer)

	k.updateWg.Add(4)

	// Start map update goroutines.
	go k.updateSymbolMap(symbolChan)
	go k.updateAddrsMap(addrChan)
	go k.updateSymByNameMap(symByNameChan)
	go k.updateSymByAddrMap(symByAddrChan)

	// Send kallsyms lines to the map update goroutines.
	if err := k.processLines([]chan *KernelSymbol{
		symbolChan,
		addrChan,
		symByNameChan,
		symByAddrChan,
	}); err != nil {
		return err
	}

	k.updateWg.Wait()

	return nil
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

// processLines processes lines from kallsyms and sends them to map update goroutines.
func (k *KernelSymbolTable) processLines(chans []chan *KernelSymbol) error {
	file, err := os.Open(kallsymsPath)
	if err != nil {
		return err
	}
	defer func() {
		if err := file.Close(); err != nil {
			logger.Warnw("error closing kallsyms file", "error", err)
		}
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		if sym := parseKallsymsLine(fields); sym != nil {
			if k.onlyRequired {
				_, symRequired := k.requiredSyms[sym.Name]
				_, addrRequired := k.requiredAddrs[sym.Address]
				if !symRequired && !addrRequired {
					continue
				}
			}
			for _, ch := range chans {
				ch <- sym
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	for _, ch := range chans {
		close(ch)
	}

	return nil
}

// updateSymbolMap updates the symbols map from the symbolChan.
func (k *KernelSymbolTable) updateSymbolMap(symbolChan chan *KernelSymbol) {
	defer k.updateWg.Done()

	for sym := range symbolChan {
		k.symbols[sym.Name] = append(k.symbols[sym.Name], sym)
	}
}

// updateAddrsMap updates the addrs map from the addrChan.
func (k *KernelSymbolTable) updateAddrsMap(addrChan chan *KernelSymbol) {
	defer k.updateWg.Done()

	for sym := range addrChan {
		key := sym.Address
		k.addrs[key] = append(k.addrs[key], sym)
	}
}

// updateSymByNameMap updates the symByName map from the symByNameChan.
func (k *KernelSymbolTable) updateSymByNameMap(symByNameChan chan *KernelSymbol) {
	defer k.updateWg.Done()

	for sym := range symByNameChan {
		key := nameAndOwner{sym.Name, sym.Owner}
		k.symByName[key] = append(k.symByName[key], sym)
	}
}

// updateSymByAddrMap updates the symByAddr map from the symByAddrChan.
func (k *KernelSymbolTable) updateSymByAddrMap(symByAddrChan chan *KernelSymbol) {
	defer k.updateWg.Done()

	for sym := range symByAddrChan {
		key := addrAndOwner{sym.Address, sym.Owner}
		k.symByAddr[key] = append(k.symByAddr[key], sym)
	}
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

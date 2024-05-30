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
	chanBuffer   = 112800
)

type KernelSymbol struct {
	Name    string
	Type    string
	Address uint64
	Owner   string
}

func symNotFoundErr(v interface{}) error {
	return fmt.Errorf("symbol not found: %v", v)
}

//
// Interface implementation
//

type name string

type addr uint64

type nameAndOwner struct {
	name  string
	owner string
}

type addrAndOwner struct {
	addr  uint64
	owner string
}

type KernelSymbolTable struct {
	symbols       map[name][]*KernelSymbol
	addrs         map[addr][]*KernelSymbol
	requiredSyms  map[string]struct{}
	requiredAddrs map[uint64]struct{}
	onlyRequired  bool
	symByName     map[nameAndOwner][]*KernelSymbol
	symByAddr     map[addrAndOwner][]*KernelSymbol
	updateLock    *sync.Mutex
	updateWg      *sync.WaitGroup
}

func NewKernelSymbolTable(opts ...KSymbTableOption) (*KernelSymbolTable, error) {
	k := KernelSymbolTable{
		updateLock: &sync.Mutex{},
	}
	for _, opt := range opts {
		err := opt(&k)
		if err != nil {
			return nil, err
		}
	}

	k.onlyRequired = k.requiredAddrs != nil || k.requiredSyms != nil

	return &k, k.Refresh()
}

type KSymbTableOption func(k *KernelSymbolTable) error

func WithRequiredSymbols(reqSyms []string) KSymbTableOption {
	return func(k *KernelSymbolTable) error {
		k.requiredSyms = sliceToValidationMap(reqSyms)
		return nil
	}
}

func WithRequiredAddresses(reqAddrs []uint64) KSymbTableOption {
	return func(k *KernelSymbolTable) error {
		k.requiredAddrs = sliceToValidationMap(reqAddrs)
		return nil
	}
}

//
// Getters (return a copy of the symbol for thread safety).
//

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
// NOTE: If table is in required only mode, method will add the new symbol
// and rescan the file.
func (k *KernelSymbolTable) GetSymbolByName(n string) ([]KernelSymbol, error) {
	k.updateLock.Lock()
	defer k.updateLock.Unlock()

	err := k.validateOrAddRequiredSym(name(n))
	if err != nil {
		return []KernelSymbol{}, nil
	}

	symbols, exist := k.symbols[name(n)]
	if !exist {
		return []KernelSymbol{}, symNotFoundErr(n)
	}

	return copySliceOfPointersToSliceOfStructs(symbols), nil
}

// GetSymbolByAddr returns all the symbols with the given address.
// NOTE: If table is in required only mode, method will add the new symbol
// and rescan the file.
func (k *KernelSymbolTable) GetSymbolByAddr(a uint64) ([]KernelSymbol, error) {
	k.updateLock.Lock()
	defer k.updateLock.Unlock()

	err := k.validateOrAddRequiredAddr(addr(a))
	if err != nil {
		return []KernelSymbol{}, err
	}

	symbols, exist := k.addrs[addr(a)]
	if !exist {
		return []KernelSymbol{}, symNotFoundErr(a)
	}

	return copySliceOfPointersToSliceOfStructs(symbols), nil
}

// GetSymbolByOwnerAndName returns all the symbols with the given owner and name.
func (k *KernelSymbolTable) GetSymbolByOwnerAndName(o, n string) ([]KernelSymbol, error) {
	k.updateLock.Lock()
	defer k.updateLock.Unlock()

	err := k.validateOrAddRequiredSym(name(n))
	if err != nil {
		return []KernelSymbol{}, err
	}

	symbols, exist := k.symByName[nameAndOwner{n, o}]
	if !exist {
		return []KernelSymbol{}, symNotFoundErr(nameAndOwner{n, o})
	}

	return copySliceOfPointersToSliceOfStructs(symbols), nil
}

// GetSymbolByOwnerAndAddr returns all the symbols with the given owner and address.
func (k *KernelSymbolTable) GetSymbolByOwnerAndAddr(o string, a uint64) ([]KernelSymbol, error) {
	k.updateLock.Lock()
	defer k.updateLock.Unlock()

	err := k.validateOrAddRequiredAddr(addr(a))
	if err != nil {
		return []KernelSymbol{}, err
	}

	symbols, exist := k.symByAddr[addrAndOwner{a, o}]
	if !exist {
		return []KernelSymbol{}, symNotFoundErr(addrAndOwner{a, o})
	}

	return copySliceOfPointersToSliceOfStructs(symbols), nil
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
func (k *KernelSymbolTable) Refresh() error {
	// Refresh may be called internally, after lock was already takne
	needUnlock := k.updateLock.TryLock()
	if needUnlock {
		defer k.updateLock.Unlock()
	}

	// re-initialize the maps to include all new symbols.
	k.symbols = make(map[name][]*KernelSymbol)
	k.addrs = make(map[addr][]*KernelSymbol)
	k.symByName = make(map[nameAndOwner][]*KernelSymbol)
	k.symByAddr = make(map[addrAndOwner][]*KernelSymbol)

	// Create the channels for the map update goroutines.
	symbolChan := make(chan *KernelSymbol, chanBuffer)
	addrChan := make(chan *KernelSymbol, chanBuffer)
	symByNameChan := make(chan *KernelSymbol, chanBuffer)
	symByAddrChan := make(chan *KernelSymbol, chanBuffer)

	k.updateWg = &sync.WaitGroup{}
	k.updateWg.Add(4)

	// Start map update goroutines.
	go k.updateSymbolMap(symbolChan)
	go k.updateAddrsMap(addrChan)
	go k.updateSymByNameMap(symByNameChan)
	go k.updateSymByAddrMap(symByAddrChan)

	// Send kallsyms lines to the map update goroutines.
	err := k.processLines([]chan *KernelSymbol{
		symbolChan,
		addrChan,
		symByNameChan,
		symByAddrChan,
	})
	if err != nil {
		return err
	}

	// Finally, wait for the map update goroutines to finish.
	k.updateWg.Wait()

	return nil
}

//
// Private methods.
//

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

// validateOrAddRequiredSym checks if the given symbol is in the required list.
// If not, it adds it and rescans the kernel symbols.
func (k *KernelSymbolTable) validateOrAddRequiredSym(sym name) error {
	if k.onlyRequired && k.requiredSyms != nil {
		sym := string(sym)
		if _, ok := k.requiredSyms[sym]; !ok {
			k.requiredSyms[sym] = struct{}{}
			err := k.Refresh()
			return err
		}
	}

	return nil
}

// validateOrAddRequiredAddr checks if the given address is in the required list.
// If not, it adds it and rescans the kernel symbols.
func (k *KernelSymbolTable) validateOrAddRequiredAddr(addr addr) error {
	if k.onlyRequired && k.requiredAddrs != nil {
		addr := uint64(addr)
		if _, ok := k.requiredAddrs[addr]; !ok {
			k.requiredAddrs[addr] = struct{}{}
			err := k.Refresh()
			return err
		}
	}

	return nil
}

//
// Concurrency logic for updating the maps
//

// processLines process lines from kallsyms and sends them to map update goroutines.
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

	// Send all lines to all channels.
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		if sym := parseLine(fields); sym != nil {
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

	// Close all channels.
	for _, ch := range chans {
		close(ch)
	}

	return nil
}

// updateSymbolMap updates the symbols map arrived from the symbolChan.
func (k *KernelSymbolTable) updateSymbolMap(symbolChan chan *KernelSymbol) {
	defer k.updateWg.Done()

	for sym := range symbolChan {
		key := name(sym.Name)
		k.symbols[key] = append(k.symbols[key], sym)
	}
}

// updateAddrsMap updates the addrs map arrived from the addrChan.
func (k *KernelSymbolTable) updateAddrsMap(addrChan chan *KernelSymbol) {
	defer k.updateWg.Done()

	for sym := range addrChan {
		key := addr(sym.Address)
		k.addrs[key] = append(k.addrs[key], sym)
	}
}

// updateSymByNameMap updates the symByName map arrived from the symByNameChan.
func (k *KernelSymbolTable) updateSymByNameMap(symByNameChan chan *KernelSymbol) {
	defer k.updateWg.Done()

	for sym := range symByNameChan {
		key := nameAndOwner{sym.Name, sym.Owner}
		k.symByName[key] = append(k.symByName[key], sym)
	}
}

// updateSymByAddrMap updates the symByAddr map arrived from the symByAddrChan.
func (k *KernelSymbolTable) updateSymByAddrMap(symByAddrChan chan *KernelSymbol) {
	defer k.updateWg.Done()

	for sym := range symByAddrChan {
		key := addrAndOwner{sym.Address, sym.Owner}
		k.symByAddr[key] = append(k.symByAddr[key], sym)
	}
}

//
// Support functions.
//

// parseLine parses a line from /proc/kallsyms and returns a KernelSymbol.
func parseLine(line []string) *KernelSymbol {
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

func copySliceOfPointersToSliceOfStructs(s []*KernelSymbol) []KernelSymbol {
	ret := make([]KernelSymbol, 0, len(s))
	for _, v := range s {
		ret = append(ret, *v)
	}
	return ret
}

func sliceToValidationMap[T comparable](items []T) map[T]struct{} {
	res := make(map[T]struct{})
	for _, item := range items {
		res[item] = struct{}{}
	}
	return res
}

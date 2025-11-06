package events

import (
	"slices"

	"kernel.org/pub/linux/libs/security/libcap/cap"

	"github.com/aquasecurity/tracee/pkg/ebpf/probes"
)

// DependencyStrategy implements the Strategy pattern for event dependency resolution.
// It encapsulates multiple approaches to satisfying event requirements: a primary
// dependency configuration followed by an ordered sequence of fallback alternatives.
// Fallbacks are attempted sequentially in the order they appear until one succeeds
// or all options are exhausted, providing graceful degradation of functionality.
//
// Currently, fallbacks are not supporting tail calls and capabilities in the dependencies.
// Event dependencies with these dependencies and kernel symbol dependencies are not supported in fallbacks as well.
type DependencyStrategy struct {
	primary   Dependencies
	fallbacks []Dependencies
}

func NewDependencyStrategy(dependencies Dependencies) DependencyStrategy {
	return DependencyStrategy{primary: dependencies, fallbacks: nil}
}

func NewDependencyStrategyWithFallbacks(dependencies Dependencies, fallbacks []Dependencies) DependencyStrategy {
	return DependencyStrategy{primary: dependencies, fallbacks: fallbacks}
}

func (e DependencyStrategy) GetPrimaryDependencies() Dependencies {
	return e.primary
}

func (e DependencyStrategy) GetFallbackDependencies() []Dependencies {
	return e.fallbacks
}

func (e DependencyStrategy) GetFallbackAt(index int) (Dependencies, bool) {
	if index < 0 || index >= len(e.fallbacks) {
		return Dependencies{}, false
	}
	return e.fallbacks[index], true
}

func (e DependencyStrategy) GetFallbacks() []Dependencies {
	return e.fallbacks
}

// Dependencies represents a cohesive set of runtime requirements for event execution.
// It encapsulates all necessary system resources, kernel interfaces, and security
// constraints required for successful event operation.
type Dependencies struct {
	ids          []ID
	kSymbols     []KSymbol
	probes       []Probe
	tailCalls    []TailCall
	capabilities Capabilities
}

func NewDependencies(
	givenIDs []ID,
	givenkSymbols []KSymbol,
	givenProbes []Probe,
	givenTailCalls []TailCall,
	givenCapabilities Capabilities,
) Dependencies {
	return Dependencies{
		ids:          givenIDs,
		kSymbols:     givenkSymbols,
		probes:       givenProbes,
		tailCalls:    givenTailCalls,
		capabilities: givenCapabilities,
	}
}

func (d Dependencies) GetIDs() []ID {
	if d.ids == nil {
		return []ID{}
	}
	return d.ids
}

func (d Dependencies) GetKSymbols() []KSymbol {
	if d.kSymbols == nil {
		return []KSymbol{}
	}
	return d.kSymbols
}

func (d Dependencies) GetRequiredKSymbols() []KSymbol {
	var requiredKSymbols []KSymbol
	for _, kSymbol := range d.kSymbols {
		if kSymbol.required {
			requiredKSymbols = append(requiredKSymbols, kSymbol)
		}
	}
	return requiredKSymbols
}

func (d Dependencies) GetProbes() []Probe {
	if d.probes == nil {
		return []Probe{}
	}
	return d.probes
}

func (d Dependencies) GetTailCalls() []TailCall {
	if d.tailCalls == nil {
		return []TailCall{}
	}
	return d.tailCalls
}

func (d Dependencies) GetCapabilities() Capabilities {
	return d.capabilities
}

// Probe
type Probe struct {
	handle   probes.Handle
	required bool // tracee fails if probe can't be attached
}

func NewProbe(handle probes.Handle, required bool) Probe {
	return Probe{handle: handle, required: required}
}

func (p Probe) GetHandle() probes.Handle {
	return p.handle
}

func (p Probe) IsRequired() bool {
	return p.required
}

// KSymbol

type KSymbol struct {
	symbol   string
	required bool // tracee fails if symbol is not found
}

func NewKSymbol(symbol string, required bool) KSymbol {
	return KSymbol{symbol: symbol, required: required}
}

func (ks KSymbol) GetSymbolName() string {
	return ks.symbol
}

func (ks KSymbol) IsRequired() bool {
	return ks.required
}

// Capabilities

type Capabilities struct {
	base []cap.Value // always effective
	ebpf []cap.Value // effective when using eBPF
}

func NewCapabilities(base []cap.Value, ebpf []cap.Value) Capabilities {
	return Capabilities{base: base, ebpf: ebpf}
}

func (c Capabilities) GetBase() []cap.Value {
	if c.base == nil {
		return []cap.Value{}
	}
	return c.base
}

func (c Capabilities) GetEBPF() []cap.Value {
	if c.ebpf == nil {
		return []cap.Value{}
	}
	return c.ebpf
}

// TailCall

const (
	TailVfsWrite  uint32 = iota // Index of a function to be used in a bpf tailcall.
	TailVfsWritev               // Matches defined values in ebpf code for prog_array map.
	TailSendBin
	TailSendBinTP
	TailKernelWrite
	TailSchedProcessExecEventSubmit
	TailVfsRead
	TailVfsReadv
	TailProcessExecuteFailed
	TailHiddenKernelModuleProc
	TailHiddenKernelModuleKset
	TailHiddenKernelModuleModTree
	TailHiddenKernelModuleNewModOnly
	TailHiddenKernelModuleModTreeLoop
	TailIoWrite
	TailFeaturesFallback // Use the same index to make sure that the tailcall is reset
	maxTail
)

type TailCall struct {
	mapName  string
	progName string
	indexes  []uint32
}

func (tc TailCall) GetIndexes() []uint32 {
	if tc.indexes == nil {
		return []uint32{}
	}
	return tc.indexes
}

func (tc TailCall) GetMapName() string {
	return tc.mapName
}

func (tc TailCall) GetProgName() string {
	return tc.progName
}

func (tc TailCall) IsRequired() bool {
	return true // tailcalls are always required
}

func NewTailCall(mapName string, progName string, indexes []uint32) TailCall {
	return TailCall{mapName: mapName, progName: progName, indexes: indexes}
}

// NewTailCallWithMergedIndexes creates a new TailCall with merged indexes from an existing tailcall and new indexes.
// This is used when multiple events share the same map+program combination but with different indexes.
func NewTailCallWithMergedIndexes(base TailCall, additionalIndexes []uint32) TailCall {
	// Create a map to track unique indexes
	indexSet := make(map[uint32]struct{})
	for _, idx := range base.indexes {
		indexSet[idx] = struct{}{}
	}
	for _, idx := range additionalIndexes {
		indexSet[idx] = struct{}{}
	}

	// Convert back to slice
	mergedIndexes := make([]uint32, 0, len(indexSet))
	for idx := range indexSet {
		mergedIndexes = append(mergedIndexes, idx)
	}

	// Sort indexes so order is deterministic
	slices.Sort(mergedIndexes)

	return TailCall{
		mapName:  base.mapName,
		progName: base.progName,
		indexes:  mergedIndexes,
	}
}

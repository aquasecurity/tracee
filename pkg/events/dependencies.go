package events

import (
	"kernel.org/pub/linux/libs/security/libcap/cap"

	"github.com/aquasecurity/tracee/pkg/ebpf/probes"
)

type Dependencies struct {
	events       []ID
	kSymbols     []KSymbol
	probes       []Probe
	tailCalls    []TailCall
	capabilities Capabilities
}

func NewDependencies(
	givenEvents []ID,
	givenkSymbols []KSymbol,
	givenProbes []Probe,
	givenTailCalls []TailCall,
	givenCapabilities Capabilities,
) Dependencies {
	return Dependencies{
		events:       givenEvents,
		kSymbols:     givenkSymbols,
		probes:       givenProbes,
		tailCalls:    givenTailCalls,
		capabilities: givenCapabilities,
	}
}

func (d Dependencies) GetEvents() []ID {
	if d.events == nil {
		return []ID{}
	}
	return d.events
}

func (d Dependencies) GetKSymbols() []KSymbol {
	if d.kSymbols == nil {
		return []KSymbol{}
	}
	return d.kSymbols
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

func (ks KSymbol) GetSymbol() string {
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
	TailExecBinprm1
	TailExecBinprm2
	TailHiddenKernelModuleProc
	TailHiddenKernelModuleKset
	TailHiddenKernelModuleModTree
	TailHiddenKernelModuleNewModOnly
	MaxTail
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

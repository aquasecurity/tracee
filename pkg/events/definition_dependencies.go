package events

import (
	"fmt"

	"kernel.org/pub/linux/libs/security/libcap/cap"

	"github.com/aquasecurity/libbpfgo/helpers"

	"github.com/aquasecurity/tracee/pkg/ebpf/probes"
)

// Dependencies is a struct that holds all the dependencies of a given event definition.
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

type KernelVersionComparison int

const (
	Older KernelVersionComparison = iota
	OlderEquals
	Equals
	NewerEquals
	Newer
)

type KernelDependency struct {
	version    string
	comparison KernelVersionComparison
}

func (kernelDep KernelDependency) isKernelCompatible(osInfo *helpers.OSInfo) (bool, error) {
	comp, err := osInfo.CompareOSBaseKernelRelease(kernelDep.version)
	if err != nil {
		return false, err
	}
	depComp := kernelDep.comparison
	switch comp {
	case helpers.KernelVersionEqual:
		if depComp != Equals && depComp != OlderEquals && depComp != NewerEquals {
			return false, nil
		}
	case helpers.KernelVersionOlder:
		if depComp != Newer && depComp != NewerEquals {
			return false, nil
		}
	case helpers.KernelVersionNewer:
		if depComp != Older && depComp != OlderEquals {
			return false, nil
		}
	default:
		return false, fmt.Errorf("unknown comparison type %d", depComp)
	}
	return true, nil
}

type Probe struct {
	handle          probes.Handle
	required        bool               // the event is cancelled if probe can't be attached
	relevantKernels []KernelDependency // set of comparisons to determine kernel versions for which to attach the probe
}

func (p Probe) GetHandle() probes.Handle {
	return p.handle
}

// IsRequired determine if the probe is required for the event to work properly
func (p Probe) IsRequired() bool {
	return p.required
}

// IsOsCompatible determine if the probe should be attached in current environment
// If a required probe is not relevant in the environment, then the event won't be cancelled as an
// attempt to attach it won't be initiated in the first place.
func (p Probe) IsOsCompatible(osInfo *helpers.OSInfo) (bool, error) {
	for _, kernelDep := range p.relevantKernels {
		isCompatible, err := kernelDep.isKernelCompatible(osInfo)
		if err != nil || !isCompatible {
			return false, err
		}
	}
	return true, nil
}

// KSymbol

type KSymbol struct {
	symbol   string
	required bool // tracee fails if symbol is not found
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
	TailSecurityBprmCredsForExec1
	TailSecurityBprmCredsForExec2
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

package events

import (
	"kernel.org/pub/linux/libs/security/libcap/cap"

	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/ebpf/probes"
)

type Dependencies struct {
	Events       []ID
	KSymbols     []KSymbol
	Probes       []Probe
	TailCalls    []TailCall
	Capabilities Capabilities
}

// Probe

type Probe struct {
	Handle   probes.Handle
	Required bool
}

// KSymbol

type KSymbol struct {
	Symbol   string
	Required bool
}

// Capabilities

type Capabilities map[capabilities.RingType][]cap.Value // array of needed capabilities per ring type

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
	return tc.indexes
}

func (tc TailCall) GetIndexesLen() int {
	return len(tc.indexes)
}

func (tc TailCall) GetMapName() string {
	return tc.mapName
}

func (tc TailCall) GetProgName() string {
	return tc.progName
}

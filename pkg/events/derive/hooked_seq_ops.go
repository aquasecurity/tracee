package derive

import (
	"github.com/aquasecurity/libbpfgo/helpers"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/aquasecurity/tracee/types/trace"
)

func HookedSeqOps(kernelSymbols *helpers.KernelSymbolTable) events.DeriveFunction {
	return singleEventDeriveFunc(events.HookedSyscalls, deriveHookedSeqOpsArgs(kernelSymbols))

}

func deriveHookedSeqOpsArgs(kernelSymbols *helpers.KernelSymbolTable) deriveArgsFunction {
	return func(event trace.Event) ([]interface{}, error) {
		seqOpsArr, err := parse.ArgUlongArrVal(&event, "net_seq_ops")
		if err != nil || len(seqOpsArr) < 1 {
			return nil, err
		}
		seqOpsName := utils.ParseSymbol(seqOpsArr[0], kernelSymbols).Name
		hookedSeqOps := make([]trace.HookedSymbolData, 0)
		for _, addr := range seqOpsArr[1:] {
			inTextSegment, err := kernelSymbols.TextSegmentContains(addr)
			if err != nil {
				continue
			}
			if !inTextSegment {
				hookingFunction := utils.ParseSymbol(addr, kernelSymbols)
				hookedSeqOps = append(hookedSeqOps, trace.HookedSymbolData{SymbolName: hookingFunction.Name, ModuleOwner: hookingFunction.Owner})
			}
		}
		return []interface{}{seqOpsName, hookedSeqOps}, nil
	}
}

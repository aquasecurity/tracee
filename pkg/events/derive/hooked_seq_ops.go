package derive

import (
	"github.com/aquasecurity/libbpfgo/helpers"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/aquasecurity/tracee/types/trace"
)

// Struct names for the interfaces HookedSeqOpsEventID checks for hooks
// The show,start,next and stop operation function pointers will be checked for each of those
var NetSeqOps = [6]string{
	"tcp4_seq_ops",
	"tcp6_seq_ops",
	"udp_seq_ops",
	"udp6_seq_ops",
	"raw_seq_ops",
	"raw6_seq_ops",
}

var NetSeqOpsFuncs = [4]string{
	"show",
	"start",
	"next",
	"stop",
}

func HookedSeqOps(kernelSymbols *helpers.KernelSymbolTable) deriveFunction {
	return deriveSingleEvent(events.HookedSeqOps, deriveHookedSeqOpsArgs(kernelSymbols))

}

func deriveHookedSeqOpsArgs(kernelSymbols *helpers.KernelSymbolTable) deriveArgsFunction {
	return func(event trace.Event) ([]interface{}, error) {
		seqOpsArr, err := parse.ArgUlongArrVal(&event, "net_seq_ops")
		if err != nil || len(seqOpsArr) < 1 {
			return nil, err
		}
		hookedSeqOps := make(map[string]trace.HookedSymbolData, 0)
		for i, addr := range seqOpsArr {
			inTextSegment, err := kernelSymbols.TextSegmentContains(addr)
			if err != nil {
				continue
			}
			if !inTextSegment {
				hookingFunction := utils.ParseSymbol(addr, kernelSymbols)
				seqOpsStruct := NetSeqOps[i/4]
				seqOpsFunc := NetSeqOpsFuncs[i%4]
				hookedSeqOps[seqOpsStruct+"_"+seqOpsFunc] =
					trace.HookedSymbolData{SymbolName: hookingFunction.Name, ModuleOwner: hookingFunction.Owner}
			}
		}
		return []interface{}{hookedSeqOps}, nil
	}
}

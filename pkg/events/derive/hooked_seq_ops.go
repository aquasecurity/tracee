package derive

import (
	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/datastores/symbol"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
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

func HookedSeqOps(kernelSymbols *symbol.KernelSymbolTable) DeriveFunction {
	return deriveSingleEvent(events.HookedSeqOps, deriveHookedSeqOpsArgs(kernelSymbols))
}

func deriveHookedSeqOpsArgs(kernelSymbols *symbol.KernelSymbolTable) deriveArgsFunction {
	return func(event *trace.Event) ([]interface{}, error) {
		seqOpsArr, err := parse.ArgVal[[]uint64](event.Args, "net_seq_ops")
		if err != nil || len(seqOpsArr) < 1 {
			return nil, errfmt.WrapError(err)
		}
		hookedSeqOps := make(map[string]trace.HookedSymbolData, 0)
		for i, addr := range seqOpsArr {
			// text segment check is done in kernel, marked as 0
			if addr == 0 {
				continue
			}
			hookingFunction := kernelSymbols.GetPotentiallyHiddenSymbolByAddr(addr)[0]
			// Indexing logic is as follows:
			// For an address at index i:
			//   - seqOpsStruct = NetSeqOps[i/4]
			//   - seqOpsFunc = NetSeqOpsFuncs[i%4]
			seqOpsStruct, seqOpsFunc := getSeqOpsSymbols(i)
			if seqOpsStruct == "" || seqOpsFunc == "" {
				logger.Errorw("failed to get seq ops symbols - this should not happen", "index", i)
				continue
			}
			hookedSeqOps[seqOpsStruct+"_"+seqOpsFunc] =
				trace.HookedSymbolData{SymbolName: hookingFunction.Name, ModuleOwner: hookingFunction.Owner}
		}
		return []interface{}{hookedSeqOps}, nil
	}
}

func getSeqOpsSymbols(index int) (seqOpsStruct string, seqOpsFunc string) {
	seqOpsStruct = NetSeqOps[index/4]
	seqOpsFunc = NetSeqOpsFuncs[index%4]
	if seqOpsStruct == "" || seqOpsFunc == "" {
		return "", ""
	}
	return seqOpsStruct, seqOpsFunc
}

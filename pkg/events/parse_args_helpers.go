package events

import (
	"github.com/aquasecurity/tracee/pkg/events/parsers"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/trace"
)

func parseMMapProt(arg *trace.Argument, prot uint64) {
	mmapProtArgument := parsers.ParseMmapProt(prot)
	arg.Type = "string"
	arg.Value = mmapProtArgument.String()
}

func parseSocketDomainArgument(arg *trace.Argument, domain uint64) {
	arg.Type = "string"
	socketDomainArgument, err := parsers.ParseSocketDomainArgument(domain)
	if err != nil {
		arg.Value = ""
		return
	}
	arg.Value = socketDomainArgument.String()
}

func parseSocketType(arg *trace.Argument, typ uint64) {
	arg.Type = "string"
	socketTypeArgument, err := parsers.ParseSocketType(typ)
	if err != nil {
		arg.Value = ""
		return
	}
	arg.Value = socketTypeArgument.String()
}

func parseInodeMode(arg *trace.Argument, mode uint64) {
	arg.Type = "string"
	inodeModeArgument, err := parsers.ParseInodeMode(mode)
	if err != nil {
		arg.Value = ""
		return
	}
	arg.Value = inodeModeArgument.String()
}

func parseBPFProgType(arg *trace.Argument, progType uint64) {
	arg.Type = "string"
	bpfProgTypeArgument, err := parsers.ParseBPFProgType(progType)
	if err != nil {
		arg.Value = ""
		return
	}
	arg.Value = bpfProgTypeArgument.String()
}

func parseCapability(arg *trace.Argument, capability uint64) {
	arg.Type = "string"
	capabilityFlagArgument, err := parsers.ParseCapability(capability)
	if err != nil {
		arg.Value = ""
		return
	}
	arg.Value = capabilityFlagArgument.String()
}

func parseMemProtAlert(arg *trace.Argument, alert uint32) {
	arg.Type = "string"
	arg.Value = trace.MemProtAlert(alert).String()
}

func parseSyscall(arg *trace.Argument, id int32) {
	if Core.IsDefined(ID(id)) {
		eventDefinition := Core.GetDefinitionByID(ID(id))
		if eventDefinition.IsSyscall() {
			arg.Value = eventDefinition.GetName()
			arg.Type = "string"
		}
	}
}

func parsePtraceRequestArgument(arg *trace.Argument, req uint64) {
	arg.Type = "string"
	ptraceRequestArgument, err := parsers.ParsePtraceRequestArgument(req)
	if err != nil {
		arg.Value = ""
		return
	}
	arg.Value = ptraceRequestArgument.String()
}

func parsePrctlOption(arg *trace.Argument, opt uint64) {
	arg.Type = "string"
	prctlOptionArgument, err := parsers.ParsePrctlOption(opt)
	if err != nil {
		arg.Value = ""
		return
	}
	arg.Value = prctlOptionArgument.String()
}

func parseSocketcallCall(arg *trace.Argument, call uint64) {
	arg.Type = "string"
	socketcallArgument, err := parsers.ParseSocketcallCall(call)
	if err != nil {
		arg.Value = ""
		return
	}
	arg.Value = socketcallArgument.String()
}

func parseAccessMode(arg *trace.Argument, mode uint64) {
	arg.Type = "string"
	accessModeArgument, err := parsers.ParseAccessMode(mode)
	if err != nil {
		arg.Value = ""
		return
	}
	arg.Value = accessModeArgument.String()
}

func parseExecFlag(arg *trace.Argument, flags uint64) {
	arg.Type = "string"
	execFlagArgument, err := parsers.ParseExecFlag(flags)
	if err != nil {
		arg.Value = ""
		return
	}
	arg.Value = execFlagArgument.String()
}

func parseOpenFlagArgument(arg *trace.Argument, flags uint64) {
	arg.Type = "string"
	openFlagArgument, err := parsers.ParseOpenFlagArgument(flags)
	if err != nil {
		arg.Value = ""
		return
	}
	arg.Value = openFlagArgument.String()
}

func parseCloneFlags(arg *trace.Argument, flags uint64) {
	arg.Type = "string"
	cloneFlagArgument, err := parsers.ParseCloneFlags(flags)
	if err != nil {
		arg.Value = ""
		return
	}
	arg.Value = cloneFlagArgument.String()
}

func parseBPFCmd(arg *trace.Argument, cmd uint64) {
	arg.Type = "string"
	bpfCommandArgument, err := parsers.ParseBPFCmd(cmd)
	if err != nil {
		arg.Value = ""
		return
	}
	arg.Value = bpfCommandArgument.String()
}

func parseSocketLevel(arg *trace.Argument, level uint64) {
	arg.Type = "string"
	socketLevelArgument, err := parsers.ParseSocketLevel(level)
	if err != nil {
		arg.Value = ""
		return
	}
	arg.Value = socketLevelArgument.String()
}

func parseGetSocketOption(arg *trace.Argument, opt uint64, evtID ID) {
	var optionNameArgument parsers.SocketOptionArgument
	var err error
	if evtID == Getsockopt {
		optionNameArgument, err = parsers.ParseGetSocketOption(uint64(opt))
	} else {
		optionNameArgument, err = parsers.ParseSetSocketOption(uint64(opt))
	}
	arg.Type = "string"
	if err == nil {
		arg.Value = optionNameArgument.String()
	} else {
		arg.Value = ""
	}
}

func parseFsNotifyObjType(arg *trace.Argument, objType uint64) {
	arg.Type = "string"
	fsNotifyObjTypeArgument, err := parsers.ParseFsNotifyObjType(objType)
	if err != nil {
		arg.Value = ""
		return
	}
	arg.Value = fsNotifyObjTypeArgument.String()
}
func parseBpfHelpersUsage(arg *trace.Argument, helpersList []uint64) {
	var usedHelpers []string

	for i := 0; i < len(helpersList)*64; i++ {
		if (helpersList[i/64] & (1 << (i % 64))) > 0 {
			// helper number <i> is used. get its name from libbpfgo
			bpfHelper, err := parsers.ParseBPFFunc(uint64(i))
			if err != nil {
				continue
			}
			usedHelpers = append(usedHelpers, bpfHelper.String())
		}
	}

	arg.Type = "const char**"
	arg.Value = usedHelpers
}

func parseBpfAttachType(arg *trace.Argument, attachType int32) {
	arg.Type = "string"

	var attTypeName string

	switch attachType {
	case 0:
		attTypeName = "raw_tracepoint"
	case 1:
		attTypeName = "tracepoint"
	case 2:
		attTypeName = "kprobe"
	case 3:
		attTypeName = "kretprobe"
	case 4:
		attTypeName = "uprobe"
	case 5:
		attTypeName = "uretprobe"
	default:
		arg.Value = ""
		logger.Errorw("Unknown attach_type got from bpf_attach event")
		return
	}

	arg.Value = attTypeName
}

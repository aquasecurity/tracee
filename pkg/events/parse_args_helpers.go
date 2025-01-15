package events

import (
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/aquasecurity/tracee/pkg/events/parsers"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/trace"
)

func parseDirfdAt(arg *trace.Argument, dirfd uint64) {
	if int32(dirfd) == unix.AT_FDCWD {
		arg.Type = "string"
		arg.Value = "AT_FDCWD"
		return
	}
}

func parseMMapProt(arg *trace.Argument, prot uint64) {
	mmapProtArgument := parsers.ParseMmapProt(prot)
	arg.Type = "string"
	arg.Value = mmapProtArgument.String()
}

func parseSocketDomainArgument(arg *trace.Argument, domain uint64) {
	arg.Type = "string"
	socketDomainArgument, err := parsers.ParseSocketDomainArgument(domain)
	if err != nil {
		arg.Value = strconv.FormatUint(domain, 10)
		return
	}
	arg.Value = socketDomainArgument
}

func parseSocketType(arg *trace.Argument, typ uint64) {
	arg.Type = "string"
	socketTypeArgument, err := parsers.ParseSocketType(typ)
	if err != nil {
		arg.Value = strconv.FormatUint(typ, 10)
		return
	}
	arg.Value = socketTypeArgument.String()
}

func parseInodeMode(arg *trace.Argument, mode uint64) {
	arg.Type = "string"
	inodeModeArgument, err := parsers.ParseInodeMode(mode)
	if err != nil {
		arg.Value = strconv.FormatUint(mode, 10)
		return
	}
	arg.Value = inodeModeArgument.String()
}

func parseBPFProgType(arg *trace.Argument, progType uint64) {
	arg.Type = "string"
	bpfProgTypeArgument, err := parsers.ParseBPFProgType(progType)
	if err != nil {
		arg.Value = strconv.FormatUint(progType, 10)
		return
	}
	arg.Value = bpfProgTypeArgument.String()
}

func parseCapability(arg *trace.Argument, capability uint64) {
	arg.Type = "string"
	capabilityFlagArgument, err := parsers.ParseCapability(capability)
	if err != nil {
		arg.Value = strconv.FormatUint(capability, 10)
		return
	}
	arg.Value = capabilityFlagArgument
}

func parseMemProtAlert(arg *trace.Argument, alert uint32) {
	arg.Type = "string"
	arg.Value = trace.MemProtAlert(alert).String()
}

func parseSyscall(arg *trace.Argument, id int32) {
	// Bypass the lock contention accessing the read-only map directly, avoiding
	// locking the map for reading.
	//
	// NOTE: This might cause data races in the future if the map is modified.
	// One solution to keep better CPU time is to segregate the map into two maps:
	// one for proper core (read-only) events and another for the dynamic events.
	arg.Type = "string"
	def, ok := CoreEvents[ID(id)]
	if !ok || !def.IsSyscall() {
		arg.Value = strconv.FormatInt(int64(id), 10)
		return
	}

	arg.Value = def.GetName()
}

func parsePtraceRequestArgument(arg *trace.Argument, req uint64) {
	arg.Type = "string"
	ptraceRequestArgument, err := parsers.ParsePtraceRequestArgument(req)
	if err != nil {
		arg.Value = strconv.FormatUint(req, 10)
		return
	}
	arg.Value = ptraceRequestArgument
}

func parsePrctlOption(arg *trace.Argument, option uint64) {
	arg.Type = "string"
	prctlOptionArgument, err := parsers.ParsePrctlOption(option)
	if err != nil {
		arg.Value = strconv.FormatUint(option, 10)
		return
	}
	arg.Value = prctlOptionArgument
}

func parseSocketcallCall(arg *trace.Argument, call uint64) {
	arg.Type = "string"
	socketCallArgument, err := parsers.ParseSocketcallCall(call)
	if err != nil {
		arg.Value = strconv.FormatUint(call, 10)
		return
	}
	arg.Value = socketCallArgument
}

func parseAccessMode(arg *trace.Argument, mode uint64) {
	arg.Type = "string"
	accessModeArgument, err := parsers.ParseAccessMode(mode)
	if err != nil {
		arg.Value = strconv.FormatUint(mode, 10)
		return
	}
	arg.Value = accessModeArgument
}

func parseFaccessatFlag(arg *trace.Argument, flags uint64) {
	arg.Type = "string"
	faccessatFlagArgument, err := parsers.ParseFaccessatFlag(flags)
	if err != nil {
		arg.Value = strconv.FormatUint(flags, 10)
		return
	}
	arg.Value = faccessatFlagArgument
}

func parseFchmodatFlag(arg *trace.Argument, flags uint64) {
	arg.Type = "string"
	fchmodatFlagArgument, err := parsers.ParseFchmodatFlag(flags)
	if err != nil {
		arg.Value = strconv.FormatUint(flags, 10)
		return
	}
	arg.Value = fchmodatFlagArgument
}

func parseExecveatFlag(arg *trace.Argument, flags uint64) {
	arg.Type = "string"
	execFlagArgument, err := parsers.ParseExecveatFlag(flags)
	if err != nil {
		arg.Value = strconv.FormatUint(flags, 10)
		return
	}
	arg.Value = execFlagArgument
}

func parseOpenFlagArgument(arg *trace.Argument, flags uint64) {
	arg.Type = "string"
	openFlagArgument, err := parsers.ParseOpenFlagArgument(flags)
	if err != nil {
		arg.Value = strconv.FormatUint(flags, 10)
		return
	}
	arg.Value = openFlagArgument
}

func parseCloneFlags(arg *trace.Argument, flags uint64) {
	arg.Type = "string"
	cloneFlagArgument, err := parsers.ParseCloneFlags(flags)
	if err != nil {
		arg.Value = strconv.FormatUint(flags, 10)
		return
	}
	arg.Value = cloneFlagArgument
}

func parseBPFCmd(arg *trace.Argument, cmd uint64) {
	arg.Type = "string"
	bpfCommandArgument, err := parsers.ParseBPFCmd(cmd)
	if err != nil {
		arg.Value = strconv.FormatUint(cmd, 10)
		return
	}
	arg.Value = bpfCommandArgument
}

func parseSocketLevel(arg *trace.Argument, level uint64) {
	arg.Type = "string"
	socketLevelArgument, err := parsers.ParseSocketLevel(level)
	if err != nil {
		arg.Value = strconv.FormatUint(level, 10)
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
		arg.Value = strconv.FormatUint(opt, 10)
	}
}

func parseFsNotifyObjType(arg *trace.Argument, objType uint64) {
	arg.Type = "string"
	fsNotifyObjTypeArgument, err := parsers.ParseFsNotifyObjType(objType)
	if err != nil {
		arg.Value = strconv.FormatUint(objType, 10)
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
				usedHelpers = append(usedHelpers, strconv.FormatInt(int64(i), 10))
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
		attTypeName = strconv.FormatInt(int64(attachType), 10)
		logger.Errorw("Unknown attach_type got from bpf_attach event")
	}

	arg.Value = attTypeName
}

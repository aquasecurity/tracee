package events

import (
	"strconv"

	"golang.org/x/sys/unix"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/common/parsers"
	"github.com/aquasecurity/tracee/types/trace"
)

// Protobuf event parsing helper functions
// These work with pb.EventValue and modify the Value oneof field in-place

func parseDirfdAt(ev *pb.EventValue, dirfd uint64) {
	if int32(dirfd) == unix.AT_FDCWD {
		ev.Value = &pb.EventValue_Str{Str: "AT_FDCWD"}
	}
}

func parseMMapProt(ev *pb.EventValue, prot uint64) {
	mmapProtArgument := parsers.ParseMmapProt(prot)
	ev.Value = &pb.EventValue_Str{Str: mmapProtArgument.String()}
}

func parseSocketDomainArgument(ev *pb.EventValue, domain uint64) {
	socketDomainArgument, err := parsers.ParseSocketDomainArgument(domain)
	if err != nil {
		ev.Value = &pb.EventValue_Str{Str: strconv.FormatUint(domain, 10)}
		return
	}
	ev.Value = &pb.EventValue_Str{Str: socketDomainArgument}
}

func parseSocketType(ev *pb.EventValue, typ uint64) {
	socketTypeArgument, err := parsers.ParseSocketType(typ)
	if err != nil {
		ev.Value = &pb.EventValue_Str{Str: strconv.FormatUint(typ, 10)}
		return
	}
	ev.Value = &pb.EventValue_Str{Str: socketTypeArgument.String()}
}

func parseInodeMode(ev *pb.EventValue, mode uint64) {
	inodeModeArgument, err := parsers.ParseInodeMode(mode)
	if err != nil {
		ev.Value = &pb.EventValue_Str{Str: strconv.FormatUint(mode, 10)}
		return
	}
	ev.Value = &pb.EventValue_Str{Str: inodeModeArgument.String()}
}

func parseBPFProgType(ev *pb.EventValue, progType uint64) {
	bpfProgTypeArgument, err := parsers.ParseBPFProgType(progType)
	if err != nil {
		ev.Value = &pb.EventValue_Str{Str: strconv.FormatUint(progType, 10)}
		return
	}
	ev.Value = &pb.EventValue_Str{Str: bpfProgTypeArgument.String()}
}

func parseCapability(ev *pb.EventValue, capability uint64) {
	capabilityFlagArgument, err := parsers.ParseCapability(capability)
	if err != nil {
		ev.Value = &pb.EventValue_Str{Str: strconv.FormatUint(capability, 10)}
		return
	}
	ev.Value = &pb.EventValue_Str{Str: capabilityFlagArgument}
}

func parseMemProtAlert(ev *pb.EventValue, alert uint32) {
	ev.Value = &pb.EventValue_Str{Str: trace.MemProtAlert(alert).String()}
}

func parseSyscall(ev *pb.EventValue, id int32) {
	def, ok := CoreEvents[ID(id)]
	if !ok || !def.IsSyscall() {
		ev.Value = &pb.EventValue_Str{Str: strconv.FormatInt(int64(id), 10)}
		return
	}
	ev.Value = &pb.EventValue_Str{Str: def.GetName()}
}

func parsePtraceRequestArgument(ev *pb.EventValue, req uint64) {
	ptraceRequestArgument, err := parsers.ParsePtraceRequestArgument(req)
	if err != nil {
		ev.Value = &pb.EventValue_Str{Str: strconv.FormatUint(req, 10)}
		return
	}
	ev.Value = &pb.EventValue_Str{Str: ptraceRequestArgument}
}

func parsePrctlOption(ev *pb.EventValue, option uint64) {
	prctlOptionArgument, err := parsers.ParsePrctlOption(option)
	if err != nil {
		ev.Value = &pb.EventValue_Str{Str: strconv.FormatUint(option, 10)}
		return
	}
	ev.Value = &pb.EventValue_Str{Str: prctlOptionArgument}
}

func parseSocketcallCall(ev *pb.EventValue, call uint64) {
	socketCallArgument, err := parsers.ParseSocketcallCall(call)
	if err != nil {
		ev.Value = &pb.EventValue_Str{Str: strconv.FormatUint(call, 10)}
		return
	}
	ev.Value = &pb.EventValue_Str{Str: socketCallArgument}
}

func parseAccessMode(ev *pb.EventValue, mode uint64) {
	accessModeArgument, err := parsers.ParseAccessMode(mode)
	if err != nil {
		ev.Value = &pb.EventValue_Str{Str: strconv.FormatUint(mode, 10)}
		return
	}
	ev.Value = &pb.EventValue_Str{Str: accessModeArgument}
}

func parseFaccessatFlag(ev *pb.EventValue, flags uint64) {
	faccessatFlagArgument, err := parsers.ParseFaccessatFlag(flags)
	if err != nil {
		ev.Value = &pb.EventValue_Str{Str: strconv.FormatUint(flags, 10)}
		return
	}
	ev.Value = &pb.EventValue_Str{Str: faccessatFlagArgument}
}

func parseFchmodatFlag(ev *pb.EventValue, flags uint64) {
	fchmodatFlagArgument, err := parsers.ParseFchmodatFlag(flags)
	if err != nil {
		ev.Value = &pb.EventValue_Str{Str: strconv.FormatUint(flags, 10)}
		return
	}
	ev.Value = &pb.EventValue_Str{Str: fchmodatFlagArgument}
}

func parseExecveatFlag(ev *pb.EventValue, flags uint64) {
	execFlagArgument, err := parsers.ParseExecveatFlag(flags)
	if err != nil {
		ev.Value = &pb.EventValue_Str{Str: strconv.FormatUint(flags, 10)}
		return
	}
	ev.Value = &pb.EventValue_Str{Str: execFlagArgument}
}

func parseOpenFlagArgument(ev *pb.EventValue, flags uint64) {
	openFlagArgument, err := parsers.ParseOpenFlagArgument(flags)
	if err != nil {
		ev.Value = &pb.EventValue_Str{Str: strconv.FormatUint(flags, 10)}
		return
	}
	ev.Value = &pb.EventValue_Str{Str: openFlagArgument}
}

func parseCloneFlags(ev *pb.EventValue, flags uint64) {
	cloneFlagArgument, err := parsers.ParseCloneFlags(flags)
	if err != nil {
		ev.Value = &pb.EventValue_Str{Str: strconv.FormatUint(flags, 10)}
		return
	}
	ev.Value = &pb.EventValue_Str{Str: cloneFlagArgument}
}

func parseBPFCmd(ev *pb.EventValue, cmd uint64) {
	bpfCommandArgument, err := parsers.ParseBPFCmd(cmd)
	if err != nil {
		ev.Value = &pb.EventValue_Str{Str: strconv.FormatUint(cmd, 10)}
		return
	}
	ev.Value = &pb.EventValue_Str{Str: bpfCommandArgument}
}

func parseKernelReadType(ev *pb.EventValue, readFileId int32) {
	ev.Value = &pb.EventValue_Str{Str: trace.KernelReadType(readFileId).String()}
}

func parseSocketLevel(ev *pb.EventValue, level uint64) {
	socketLevelArgument, err := parsers.ParseSocketLevel(level)
	if err != nil {
		ev.Value = &pb.EventValue_Str{Str: strconv.FormatUint(level, 10)}
		return
	}
	ev.Value = &pb.EventValue_Str{Str: socketLevelArgument.String()}
}

func parseGetSocketOption(ev *pb.EventValue, opt uint64, evtID ID) {
	var optionNameArgument parsers.SocketOptionArgument
	var err error
	if evtID == Getsockopt {
		optionNameArgument, err = parsers.ParseGetSocketOption(uint64(opt))
	} else {
		optionNameArgument, err = parsers.ParseSetSocketOption(uint64(opt))
	}
	if err == nil {
		ev.Value = &pb.EventValue_Str{Str: optionNameArgument.String()}
	} else {
		ev.Value = &pb.EventValue_Str{Str: strconv.FormatUint(opt, 10)}
	}
}

func parseFsNotifyObjType(ev *pb.EventValue, objType uint64) {
	fsNotifyObjTypeArgument, err := parsers.ParseFsNotifyObjType(objType)
	if err != nil {
		ev.Value = &pb.EventValue_Str{Str: strconv.FormatUint(objType, 10)}
		return
	}
	ev.Value = &pb.EventValue_Str{Str: fsNotifyObjTypeArgument.String()}
}

func parseBpfHelpersUsage(ev *pb.EventValue, helpersList []uint64) {
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

	ev.Value = &pb.EventValue_StrArray{StrArray: &pb.StringArray{Value: usedHelpers}}
}

func parseBpfAttachType(ev *pb.EventValue, attachType int32) {
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
		logger.Errorw("Unknown attach_type got from bpf_attach event", "attach_type", attachType)
	}

	ev.Value = &pb.EventValue_Str{Str: attTypeName}
}

func parseMmapFlags(ev *pb.EventValue, flags uint64) {
	mmapFlagsArgument := parsers.ParseMmapFlags(flags)
	ev.Value = &pb.EventValue_Str{Str: mmapFlagsArgument.String()}
}

func parseNamespaceType(ev *pb.EventValue, nstype uint64) {
	namespaceTypeArgument := parsers.ParseNamespaceType(nstype)
	ev.Value = &pb.EventValue_Str{Str: namespaceTypeArgument.String()}
}

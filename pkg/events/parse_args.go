package events

import (
	"bytes"
	"fmt"
	"strconv"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/parsers"
	"github.com/aquasecurity/tracee/common/timeutil"
	"github.com/aquasecurity/tracee/types/trace"
)

// ParseDataFields parses the protobuf event data for the given event ID.
// This modifies EventValue entries in-place by updating their Value oneof field.
func ParseDataFields(data []*pb.EventValue, eventID int) error {
	// Convert pointer values to hex string format for display
	for i := range data {
		if val, ok := data[i].Value.(*pb.EventValue_Pointer); ok {
			// Format as hex string with 0x prefix
			v := []byte{'0', 'x'}
			v = strconv.AppendUint(v, val.Pointer, 16)
			data[i].Value = &pb.EventValue_Str{Str: string(v)}
		}
	}

	evtID := ID(eventID)
	switch evtID {
	case MemProtAlert:
		if alertField := GetFieldValue(data, "alert"); alertField != nil {
			if alertVal, ok := alertField.Value.(*pb.EventValue_UInt32); ok {
				parseMemProtAlert(alertField, alertVal.UInt32)
			}
		}
		if protField := GetFieldValue(data, "prot"); protField != nil {
			if protVal, ok := protField.Value.(*pb.EventValue_Int32); ok {
				parseMMapProt(protField, uint64(protVal.Int32))
			}
		}
		if prevProtField := GetFieldValue(data, "prev_prot"); prevProtField != nil {
			if prevProtVal, ok := prevProtField.Value.(*pb.EventValue_Int32); ok {
				parseMMapProt(prevProtField, uint64(prevProtVal.Int32))
			}
		}
	case SysEnter, SysExit:
		if syscallField := GetFieldValue(data, "syscall"); syscallField != nil {
			if syscallVal, ok := syscallField.Value.(*pb.EventValue_Int32); ok {
				parseSyscall(syscallField, syscallVal.Int32)
			}
		}
	case CapCapable:
		if capField := GetFieldValue(data, "cap"); capField != nil {
			if capVal, ok := capField.Value.(*pb.EventValue_Int32); ok {
				parseCapability(capField, uint64(capVal.Int32))
			}
		}
	case SecurityMmapFile, DoMmap:
		if protField := GetFieldValue(data, "prot"); protField != nil {
			if protVal, ok := protField.Value.(*pb.EventValue_UInt64); ok {
				parseMMapProt(protField, protVal.UInt64)
			}
		}
	case Mmap, Mprotect, PkeyMprotect:
		if protField := GetFieldValue(data, "prot"); protField != nil {
			if protVal, ok := protField.Value.(*pb.EventValue_Int32); ok {
				parseMMapProt(protField, uint64(protVal.Int32))
			}
		}
	case SecurityFileMprotect:
		if protField := GetFieldValue(data, "prot"); protField != nil {
			if protVal, ok := protField.Value.(*pb.EventValue_Int32); ok {
				parseMMapProt(protField, uint64(protVal.Int32))
			}
		}
		if prevProtField := GetFieldValue(data, "prev_prot"); prevProtField != nil {
			if prevProtVal, ok := prevProtField.Value.(*pb.EventValue_Int32); ok {
				parseMMapProt(prevProtField, uint64(prevProtVal.Int32))
			}
		}
	case Ptrace:
		if reqField := GetFieldValue(data, "request"); reqField != nil {
			if reqVal, ok := reqField.Value.(*pb.EventValue_Int64); ok {
				parsePtraceRequestArgument(reqField, uint64(reqVal.Int64))
			}
		}
	case Prctl, SecurityTaskPrctl:
		if optField := GetFieldValue(data, "option"); optField != nil {
			if optVal, ok := optField.Value.(*pb.EventValue_Int32); ok {
				parsePrctlOption(optField, uint64(optVal.Int32))
			}
		}
	case Socketcall:
		if callField := GetFieldValue(data, "call"); callField != nil {
			if callVal, ok := callField.Value.(*pb.EventValue_Int32); ok {
				parseSocketcallCall(callField, uint64(callVal.Int32))
			}
		}
	case Socket:
		if domField := GetFieldValue(data, "domain"); domField != nil {
			if domVal, ok := domField.Value.(*pb.EventValue_Int32); ok {
				parseSocketDomainArgument(domField, uint64(domVal.Int32))
			}
		}
		if typeField := GetFieldValue(data, "type"); typeField != nil {
			if typeVal, ok := typeField.Value.(*pb.EventValue_Int32); ok {
				parseSocketType(typeField, uint64(typeVal.Int32))
			}
		}
	case SecuritySocketCreate, SecuritySocketConnect:
		if domField := GetFieldValue(data, "family"); domField != nil {
			if domVal, ok := domField.Value.(*pb.EventValue_Int32); ok {
				parseSocketDomainArgument(domField, uint64(domVal.Int32))
			}
		}
		if typeField := GetFieldValue(data, "type"); typeField != nil {
			if typeVal, ok := typeField.Value.(*pb.EventValue_Int32); ok {
				parseSocketType(typeField, uint64(typeVal.Int32))
			}
		}
	case Access:
		if modeField := GetFieldValue(data, "mode"); modeField != nil {
			if modeVal, ok := modeField.Value.(*pb.EventValue_Int32); ok {
				parseAccessMode(modeField, uint64(modeVal.Int32))
			}
		}
	case Faccessat:
		if modeField := GetFieldValue(data, "mode"); modeField != nil {
			if modeVal, ok := modeField.Value.(*pb.EventValue_Int32); ok {
				parseAccessMode(modeField, uint64(modeVal.Int32))
			}
		}
		if flagsField := GetFieldValue(data, "flags"); flagsField != nil {
			if flagsVal, ok := flagsField.Value.(*pb.EventValue_Int32); ok {
				parseFaccessatFlag(flagsField, uint64(flagsVal.Int32))
			}
		}
	case Execveat:
		if flagsField := GetFieldValue(data, "flags"); flagsField != nil {
			if flagsVal, ok := flagsField.Value.(*pb.EventValue_Int32); ok {
				parseExecveatFlag(flagsField, uint64(flagsVal.Int32))
			}
		}
	case Open, Openat, SecurityFileOpen:
		if flagsField := GetFieldValue(data, "flags"); flagsField != nil {
			if flagsVal, ok := flagsField.Value.(*pb.EventValue_Int32); ok {
				parseOpenFlagArgument(flagsField, uint64(flagsVal.Int32))
			}
		}
	case Mknod, Mknodat, SecurityInodeMknod, Chmod, Fchmod, Fchmodat, ChmodCommon:
		if modeField := GetFieldValue(data, "mode"); modeField != nil {
			// mode is UInt32 (widened from uint16)
			if modeVal, ok := modeField.Value.(*pb.EventValue_UInt32); ok {
				parseInodeMode(modeField, uint64(modeVal.UInt32))
			}
		}
		if evtID == Fchmodat {
			if flagsField := GetFieldValue(data, "flags"); flagsField != nil {
				if flagsVal, ok := flagsField.Value.(*pb.EventValue_Int32); ok {
					parseFchmodatFlag(flagsField, uint64(flagsVal.Int32))
				}
			}
		}
	case Clone:
		if flagsField := GetFieldValue(data, "flags"); flagsField != nil {
			if flagsVal, ok := flagsField.Value.(*pb.EventValue_UInt64); ok {
				parseCloneFlags(flagsField, flagsVal.UInt64)
			}
		}
	case Bpf, SecurityBPF:
		if cmdField := GetFieldValue(data, "cmd"); cmdField != nil {
			if cmdVal, ok := cmdField.Value.(*pb.EventValue_Int32); ok {
				parseBPFCmd(cmdField, uint64(cmdVal.Int32))
			}
		}
	case SecurityKernelReadFile, SecurityPostReadFile:
		if typeField := GetFieldValue(data, "type"); typeField != nil {
			if typeVal, ok := typeField.Value.(*pb.EventValue_Int32); ok {
				parseKernelReadType(typeField, typeVal.Int32)
			}
		}
	case SchedProcessExec:
		if modeField := GetFieldValue(data, "stdin_type"); modeField != nil {
			// stdin_type is UInt32 (widened from uint16)
			if modeVal, ok := modeField.Value.(*pb.EventValue_UInt32); ok {
				parseInodeMode(modeField, uint64(modeVal.UInt32))
			}
		}
	case DirtyPipeSplice:
		if modeField := GetFieldValue(data, "in_file_type"); modeField != nil {
			// in_file_type is UInt32 (widened from uint16)
			if modeVal, ok := modeField.Value.(*pb.EventValue_UInt32); ok {
				parseInodeMode(modeField, uint64(modeVal.UInt32))
			}
		}
	case SecuritySocketSetsockopt, Setsockopt, Getsockopt:
		if levelField := GetFieldValue(data, "level"); levelField != nil {
			if levelVal, ok := levelField.Value.(*pb.EventValue_Int32); ok {
				parseSocketLevel(levelField, uint64(levelVal.Int32))
			}
		}
		if optionNameField := GetFieldValue(data, "optname"); optionNameField != nil {
			if optVal, ok := optionNameField.Value.(*pb.EventValue_Int32); ok {
				parseGetSocketOption(optionNameField, uint64(optVal.Int32), ID(eventID))
			}
		}
	case BpfAttach:
		if progTypeField := GetFieldValue(data, "prog_type"); progTypeField != nil {
			if progTypeVal, ok := progTypeField.Value.(*pb.EventValue_Int32); ok {
				parseBPFProgType(progTypeField, uint64(progTypeVal.Int32))
			}
		}
		if helpersField := GetFieldValue(data, "prog_helpers"); helpersField != nil {
			if helpersVal, ok := helpersField.Value.(*pb.EventValue_UInt64Array); ok {
				parseBpfHelpersUsage(helpersField, helpersVal.UInt64Array.Value)
			}
		}
		if attachTypeField := GetFieldValue(data, "attach_type"); attachTypeField != nil {
			if attachTypeVal, ok := attachTypeField.Value.(*pb.EventValue_Int32); ok {
				parseBpfAttachType(attachTypeField, attachTypeVal.Int32)
			}
		}
	case SecurityBpfProg:
		if progTypeField := GetFieldValue(data, "type"); progTypeField != nil {
			if progTypeVal, ok := progTypeField.Value.(*pb.EventValue_Int32); ok {
				parseBPFProgType(progTypeField, uint64(progTypeVal.Int32))
			}
		}
		if helpersField := GetFieldValue(data, "helpers"); helpersField != nil {
			if helpersVal, ok := helpersField.Value.(*pb.EventValue_UInt64Array); ok {
				parseBpfHelpersUsage(helpersField, helpersVal.UInt64Array.Value)
			}
		}
	case SecurityPathNotify:
		if maskField := GetFieldValue(data, "mask"); maskField != nil {
			if maskVal, ok := maskField.Value.(*pb.EventValue_UInt64); ok {
				maskField.Value = &pb.EventValue_Str{Str: parsers.ParseFsNotifyMask(maskVal.UInt64).String()}
			}
		}
		if objTypeField := GetFieldValue(data, "obj_type"); objTypeField != nil {
			if objTypeVal, ok := objTypeField.Value.(*pb.EventValue_UInt32); ok {
				parseFsNotifyObjType(objTypeField, uint64(objTypeVal.UInt32))
			}
		}
	case SuspiciousSyscallSource, StackPivot:
		if vmaFlagsField := GetFieldValue(data, "vma_flags"); vmaFlagsField != nil {
			if vmaFlagsVal, ok := vmaFlagsField.Value.(*pb.EventValue_UInt64); ok {
				vmaFlagsField.Value = &pb.EventValue_Str{Str: parsers.ParseVmFlags(vmaFlagsVal.UInt64).String()}
			}
		}
	}

	// Parse extended events (only available in extended builds)
	parseEventDataExtended(evtID, data)

	return nil
}

// ParseDataFieldsFDs parses file descriptor arguments in the protobuf event data.
func ParseDataFieldsFDs(data []*pb.EventValue, origTimestamp uint64, fdArgPathMap *bpf.BPFMap) error {
	if fdField := GetFieldValue(data, "fd"); fdField != nil {
		if fdVal, ok := fdField.Value.(*pb.EventValue_Int32); ok {
			fd := fdVal.Int32
			ts := origTimestamp
			bs, err := fdArgPathMap.GetValue(unsafe.Pointer(&ts))
			if err != nil {
				return errfmt.WrapError(err)
			}

			fpath := string(bytes.Trim(bs, "\x00"))
			fdField.Value = &pb.EventValue_Str{Str: fmt.Sprintf("%d=%s", fd, fpath)}
		}
	}

	if dirfdField := GetFieldValue(data, "dirfd"); dirfdField != nil {
		if dirfdVal, ok := dirfdField.Value.(*pb.EventValue_Int32); ok {
			parseDirfdAt(dirfdField, uint64(dirfdVal.Int32))
		}
	}

	return nil
}

// GetFieldValue returns the EventValue with the specified name from the data slice.
// Returns nil if not found.
func GetFieldValue(data []*pb.EventValue, name string) *pb.EventValue {
	for i := range data {
		if data[i].Name == name {
			return data[i]
		}
	}
	return nil
}

// GetArg returns the trace.Argument with the specified name from the args slice.
// Returns nil if not found.
// This function is kept for backwards compatibility with code that still uses trace.Argument.
func GetArg(args []trace.Argument, argName string) *trace.Argument {
	for i := range args {
		if args[i].Name == argName {
			return &args[i]
		}
	}

	return nil
}

// SetArgValue sets the value of an argument by name in a trace.Event.
// This function is kept for backwards compatibility with code that still uses trace.Argument.
func SetArgValue(event *trace.Event, argName string, value any) error {
	arg := GetArg(event.Args, argName)
	if arg == nil {
		return fmt.Errorf("event %s has no argument named %s", event.EventName, argName)
	}
	arg.Value = value
	return nil
}

// NormalizeTimeArgs normalizes the time arguments of an event, converting them to
// nanoseconds since the epoch.
// This function is kept for backwards compatibility with code that still uses trace.Argument.
func NormalizeTimeArgs(args []trace.Argument, timeArgNames []string) error {
	for i := range timeArgNames {
		arg := GetArg(args, timeArgNames[i])
		if arg == nil {
			return errfmt.Errorf("couldn't find argument %s", timeArgNames[i])
		}
		if arg.Value == nil {
			continue
		}

		argTime, ok := arg.Value.(uint64)
		if !ok {
			return errfmt.Errorf("argument %s is not uint64, it is %T",
				timeArgNames[i],
				arg.Value,
			)
		}
		arg.Value = timeutil.BootToEpochNS(argTime)
	}

	return nil
}

type CustomFunctionArgument struct {
	val uint64
	str string
}

func (arg CustomFunctionArgument) String() string {
	return arg.str
}
func (arg CustomFunctionArgument) Value() uint64 {
	return arg.val
}

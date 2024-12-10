package bufferdecoder

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parsers"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/trace"
)

// argType is an enum that encodes the argument types that the BPF program may write to the shared buffer
// argument types should match defined values in ebpf code
type ArgType uint8

const (
	noneT ArgType = iota
	intT
	uintT
	longT
	ulongT
	offT
	modeT
	devT
	sizeT
	pointerT
	strT
	strArrT
	sockAddrT
	bytesT
	u16T
	credT
	intArr2T
	uint64ArrT
	u8T
	timespecT
)

// These types don't match the ones defined in the ebpf code since they are not being used by syscalls arguments.
// They have their own set of value to avoid collision in the future.
const (
	argsArrT ArgType = iota + 0x80
	boolT
)

// readArgFromBuff read the next argument from the buffer.
// Return the index of the argument and the parsed argument.
func readArgFromBuff(id events.ID, ebpfMsgDecoder *EbpfDecoder, fields []trace.ArgMeta,
) (
	uint, trace.Argument, error,
) {
	var err error
	var res interface{}
	var argIdx uint8
	var arg trace.Argument

	err = ebpfMsgDecoder.DecodeUint8(&argIdx)
	if err != nil {
		return 0, arg, errfmt.Errorf("error reading arg index: %v", err)
	}
	if int(argIdx) >= len(fields) {
		return 0, arg, errfmt.Errorf("invalid arg index %d", argIdx)
	}
	arg.ArgMeta = fields[argIdx]
	argType := GetFieldType(arg.Type)

	switch argType {
	case u8T:
		var data uint8
		err = ebpfMsgDecoder.DecodeUint8(&data)
		res = data
	case u16T:
		var data uint16
		err = ebpfMsgDecoder.DecodeUint16(&data)
		res = data
	case intT:
		var data int32
		err = ebpfMsgDecoder.DecodeInt32(&data)
		res = data
	case uintT, devT, modeT:
		var data uint32
		err = ebpfMsgDecoder.DecodeUint32(&data)
		res = data
	case longT:
		var data int64
		err = ebpfMsgDecoder.DecodeInt64(&data)
		res = data
	case ulongT, offT, sizeT:
		var data uint64
		err = ebpfMsgDecoder.DecodeUint64(&data)
		res = data
	case boolT:
		var data bool
		err = ebpfMsgDecoder.DecodeBool(&data)
		res = data
	case pointerT:
		var data uint64
		err = ebpfMsgDecoder.DecodeUint64(&data)
		res = uintptr(data)
	case sockAddrT:
		res, err = readSockaddrFromBuff(ebpfMsgDecoder)
	case credT:
		var data SlimCred
		err = ebpfMsgDecoder.DecodeSlimCred(&data)
		res = trace.SlimCred(data) // here we cast to trace.SlimCred to ensure we send the public interface and not bufferdecoder.SlimCred
	case strT:
		res, err = readStringFromBuff(ebpfMsgDecoder)
	case strArrT:
		// TODO optimization: create slice after getting arrLen
		var ss []string
		var arrLen uint8
		err = ebpfMsgDecoder.DecodeUint8(&arrLen)
		if err != nil {
			return uint(argIdx), arg, errfmt.Errorf("error reading string array number of elements: %v", err)
		}
		for i := 0; i < int(arrLen); i++ {
			s, err := readStringFromBuff(ebpfMsgDecoder)
			if err != nil {
				return uint(argIdx), arg, errfmt.Errorf("error reading string element: %v", err)
			}
			ss = append(ss, s)
		}
		res = ss
	case argsArrT:
		var ss []string
		var arrLen uint32
		var argNum uint32

		err = ebpfMsgDecoder.DecodeUint32(&arrLen)
		if err != nil {
			return uint(argIdx), arg, errfmt.Errorf("error reading args array length: %v", err)
		}
		err = ebpfMsgDecoder.DecodeUint32(&argNum)
		if err != nil {
			return uint(argIdx), arg, errfmt.Errorf("error reading args number: %v", err)
		}
		resBytes, err := ReadByteSliceFromBuff(ebpfMsgDecoder, int(arrLen))
		if err != nil {
			return uint(argIdx), arg, errfmt.Errorf("error reading args array: %v", err)
		}
		ss = strings.Split(string(resBytes), "\x00")
		if ss[len(ss)-1] == "" {
			ss = ss[:len(ss)-1]
		}
		for int(argNum) > len(ss) {
			ss = append(ss, "?")
		}
		res = ss
	case bytesT:
		var size uint32
		err = ebpfMsgDecoder.DecodeUint32(&size)
		if err != nil {
			return uint(argIdx), arg, errfmt.Errorf("error reading byte array size: %v", err)
		}
		// error if byte buffer is too big (and not a network event)
		if size > 4096 && (id < events.NetPacketBase || id > events.MaxNetID) {
			return uint(argIdx), arg, errfmt.Errorf("byte array size too big: %d", size)
		}
		res, err = ReadByteSliceFromBuff(ebpfMsgDecoder, int(size))
	case intArr2T:
		var intArray [2]int32
		err = ebpfMsgDecoder.DecodeIntArray(intArray[:], 2)
		if err != nil {
			return uint(argIdx), arg, errfmt.Errorf("error reading int elements: %v", err)
		}
		res = intArray
	case uint64ArrT:
		ulongArray := make([]uint64, 0)
		err := ebpfMsgDecoder.DecodeUint64Array(&ulongArray)
		if err != nil {
			return uint(argIdx), arg, errfmt.Errorf("error reading ulong elements: %v", err)
		}
		res = ulongArray
	case timespecT:
		var sec int64
		var nsec int64
		err = ebpfMsgDecoder.DecodeInt64(&sec)
		if err != nil {
			return uint(argIdx), arg, errfmt.WrapError(err)
		}
		err = ebpfMsgDecoder.DecodeInt64(&nsec)
		res = float64(sec) + (float64(nsec) / float64(1000000000))

	default:
		// if we don't recognize the arg type, we can't parse the rest of the buffer
		return uint(argIdx), arg, errfmt.Errorf("error unknown arg type %v", argType)
	}
	if err != nil {
		return uint(argIdx), arg, errfmt.WrapError(err)
	}
	arg.Value = res
	return uint(argIdx), arg, nil
}

func GetFieldType(fieldType string) ArgType {
	switch fieldType {
	case "int", "pid_t", "uid_t", "gid_t", "mqd_t", "clockid_t", "const clockid_t", "key_t", "key_serial_t", "timer_t":
		return intT
	case "unsigned int", "u32":
		return uintT
	case "long":
		return longT
	case "unsigned long", "u64":
		return ulongT
	case "bool":
		return boolT
	case "off_t", "loff_t":
		return offT
	case "mode_t":
		return modeT
	case "dev_t":
		return devT
	case "size_t":
		return sizeT
	case "void*", "const void*":
		return pointerT
	case "char*", "const char*":
		return strT
	case "const char*const*": // used by execve(at) argv and env
		return strArrT
	case "const char**": // used by sched_process_exec argv and envp
		return argsArrT
	case "const struct sockaddr*", "struct sockaddr*":
		return sockAddrT
	case "bytes":
		return bytesT
	case "int[2]":
		return intArr2T
	case "slim_cred_t":
		return credT
	case "umode_t":
		return u16T
	case "u8":
		return u8T
	case "unsigned long[]", "[]trace.HookedSymbolData":
		return uint64ArrT
	case "struct timespec*", "const struct timespec*":
		return timespecT
	default:
		// Default to pointer (printed as hex) for unsupported types
		return pointerT
	}
}

func readSockaddrFromBuff(ebpfMsgDecoder *EbpfDecoder) (map[string]string, error) {
	res := make(map[string]string, 5)
	var family int16
	err := ebpfMsgDecoder.DecodeInt16(&family)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}
	socketDomainArg, err := parsers.ParseSocketDomainArgument(uint64(family))
	if err != nil {
		socketDomainArg = parsers.AF_UNSPEC.String()
	}
	res["sa_family"] = socketDomainArg
	switch family {
	case 1: // AF_UNIX
		/*
			http://man7.org/linux/man-pages/man7/unix.7.html
			struct sockaddr_un {
					sa_family_t sun_family;     // AF_UNIX
					char        sun_path[108];  // Pathname
			};
		*/
		sunPath, err := readStringVarFromBuff(ebpfMsgDecoder, 108)
		if err != nil {
			return nil, errfmt.Errorf("error parsing sockaddr_un: %v", err)
		}
		res["sun_path"] = sunPath
	case 2: // AF_INET
		/*
			http://man7.org/linux/man-pages/man7/ip.7.html
			struct sockaddr_in {
				sa_family_t    sin_family; // address family: AF_INET
				in_port_t      sin_port;   // port in network byte order
				struct in_addr sin_addr;   // internet address
				// byte        padding[8];// https://elixir.bootlin.com/linux/v4.20.17/source/include/uapi/linux/in.h#L232
			};
			struct in_addr {
				uint32_t       s_addr;     // address in network byte order
			};
		*/
		var port uint16
		err = ebpfMsgDecoder.DecodeUint16BigEndian(&port)
		if err != nil {
			return nil, errfmt.Errorf("error parsing sockaddr_in: %v", err)
		}
		res["sin_port"] = strconv.Itoa(int(port))
		var addr uint32
		err = ebpfMsgDecoder.DecodeUint32BigEndian(&addr)
		if err != nil {
			return nil, errfmt.Errorf("error parsing sockaddr_in: %v", err)
		}
		res["sin_addr"] = PrintUint32IP(addr)
		_, err := ReadByteSliceFromBuff(ebpfMsgDecoder, 8)
		if err != nil {
			return nil, errfmt.Errorf("error parsing sockaddr_in: %v", err)
		}
	case 10: // AF_INET6
		/*
			struct sockaddr_in6 {
				sa_family_t     sin6_family;   // AF_INET6
				in_port_t       sin6_port;     // port number
				uint32_t        sin6_flowinfo; // IPv6 flow information
				struct in6_addr sin6_addr;     // IPv6 address
				uint32_t        sin6_scope_id; // Scope ID (new in 2.4)
			};

			struct in6_addr {
				unsigned char   s6_addr[16];   // IPv6 address
			};
		*/
		var port uint16
		err = ebpfMsgDecoder.DecodeUint16BigEndian(&port)
		if err != nil {
			return nil, errfmt.Errorf("error parsing sockaddr_in6: %v", err)
		}
		res["sin6_port"] = strconv.Itoa(int(port))

		var flowinfo uint32
		err = ebpfMsgDecoder.DecodeUint32BigEndian(&flowinfo)
		if err != nil {
			return nil, errfmt.Errorf("error parsing sockaddr_in6: %v", err)
		}
		res["sin6_flowinfo"] = strconv.Itoa(int(flowinfo))
		addr, err := ReadByteSliceFromBuff(ebpfMsgDecoder, 16)
		if err != nil {
			return nil, errfmt.Errorf("error parsing sockaddr_in6: %v", err)
		}
		res["sin6_addr"] = Print16BytesSliceIP(addr)
		var scopeid uint32
		err = ebpfMsgDecoder.DecodeUint32BigEndian(&scopeid)
		if err != nil {
			return nil, errfmt.Errorf("error parsing sockaddr_in6: %v", err)
		}
		res["sin6_scopeid"] = strconv.Itoa(int(scopeid))
	}
	return res, nil
}

func readStringFromBuff(ebpfMsgDecoder *EbpfDecoder) (string, error) {
	var err error
	var size uint32
	err = ebpfMsgDecoder.DecodeUint32(&size)
	if err != nil {
		return "", errfmt.Errorf("error reading string size: %v", err)
	}
	if size > 4096 {
		return "", errfmt.Errorf("string size too big: %d", size)
	}
	res, err := ReadByteSliceFromBuff(ebpfMsgDecoder, int(size-1)) // last byte is string terminating null
	defer func() {
		var dummy int8
		err := ebpfMsgDecoder.DecodeInt8(&dummy) // discard last byte which is string terminating null
		if err != nil {
			logger.Warnw("Trying to discard last byte", "error", err)
		}
	}()
	if err != nil {
		return "", errfmt.Errorf("error reading string arg: %v", err)
	}
	return string(res), nil
}

// readStringVarFromBuff reads a null-terminated string from `buff`
// max length can be passed as `max` to optimize memory allocation, otherwise pass 0
func readStringVarFromBuff(decoder *EbpfDecoder, max int) (string, error) {
	var err error
	var char int8
	res := make([]byte, 0, max)

	err = decoder.DecodeInt8(&char)
	if err != nil {
		return "", errfmt.Errorf("error reading null terminated string: %v", err)
	}

	count := 1 // first char is already decoded
	for char != 0 && count < max {
		res = append(res, byte(char))

		// decode next char
		err = decoder.DecodeInt8(&char)
		if err != nil {
			return "", errfmt.Errorf("error reading null terminated string: %v", err)
		}
		count++
	}

	// The exact reason for this Trim is not known, so remove it for now,
	// since it increases processing time.
	// res = bytes.TrimLeft(res[:], "\000")
	decoder.cursor += max - count // move cursor to the end of the buffer
	return string(res), nil
}

func ReadByteSliceFromBuff(ebpfMsgDecoder *EbpfDecoder, len int) ([]byte, error) {
	var err error
	res := make([]byte, len)
	err = ebpfMsgDecoder.DecodeBytes(res[:], len)
	if err != nil {
		return nil, errfmt.Errorf("error reading byte array: %v", err)
	}
	return res, nil
}

// PrintUint32IP prints the IP address encoded as a uint32
func PrintUint32IP(in uint32) string {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, in)
	return ip.String()
}

// Print16BytesSliceIP prints the IP address encoded as 16 bytes long PrintBytesSliceIP
// It would be more correct to accept a [16]byte instead of variable length slice, but that would cause unnecessary memory copying and type conversions
func Print16BytesSliceIP(in []byte) string {
	ip := net.IP(in)
	return ip.String()
}

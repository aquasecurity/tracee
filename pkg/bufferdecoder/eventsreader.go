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
	decodeType := arg.DecodeAs
	if decodeType == trace.NONE_T {
		return 0, arg, errfmt.Errorf("arg \"%s\" from event %d: did not declare a decode type, this should not happen", arg.Name, id)
	}

	switch decodeType {
	case trace.U8_T:
		var data uint8
		err = ebpfMsgDecoder.DecodeUint8(&data)
		res = data
	case trace.U16_T:
		var data uint16
		err = ebpfMsgDecoder.DecodeUint16(&data)
		res = data
	case trace.INT_T:
		var data int32
		err = ebpfMsgDecoder.DecodeInt32(&data)
		res = data
	case trace.UINT_T:
		var data uint32
		err = ebpfMsgDecoder.DecodeUint32(&data)
		res = data
	case trace.LONG_T:
		var data int64
		err = ebpfMsgDecoder.DecodeInt64(&data)
		res = data
	case trace.ULONG_T:
		var data uint64
		err = ebpfMsgDecoder.DecodeUint64(&data)
		res = data
	case trace.BOOL_T:
		var data bool
		err = ebpfMsgDecoder.DecodeBool(&data)
		res = data
	case trace.POINTER_T:
		var data uint64
		err = ebpfMsgDecoder.DecodeUint64(&data)
		res = uintptr(data)
	case trace.SOCK_ADDR_T:
		res, err = readSockaddrFromBuff(ebpfMsgDecoder)
	case trace.CRED_T:
		var data SlimCred
		err = ebpfMsgDecoder.DecodeSlimCred(&data)
		res = trace.SlimCred(data) // here we cast to trace.SlimCred to ensure we send the public interface and not bufferdecoder.SlimCred
	case trace.STR_T:
		res, err = readStringFromBuff(ebpfMsgDecoder)
	case trace.STR_ARR_T:
		var arrLen uint8
		err = ebpfMsgDecoder.DecodeUint8(&arrLen)
		if err != nil {
			return uint(argIdx), arg, errfmt.Errorf("error reading string array number of elements: %v", err)
		}
		strSlice := make([]string, 0, arrLen)
		for i := 0; i < int(arrLen); i++ {
			s, err := readStringFromBuff(ebpfMsgDecoder)
			if err != nil {
				return uint(argIdx), arg, errfmt.Errorf("error reading string element: %v", err)
			}
			strSlice = append(strSlice, s)
		}
		res = strSlice
	case trace.ARGS_ARR_T:
		var strSlice []string
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
		resBytes, err := ebpfMsgDecoder.ReadBytesLen(int(arrLen))
		if err != nil {
			return uint(argIdx), arg, errfmt.Errorf("error reading args array: %v", err)
		}
		strSlice = strings.Split(string(resBytes), "\x00")
		if strSlice[len(strSlice)-1] == "" {
			strSlice = strSlice[:len(strSlice)-1]
		}
		for int(argNum) > len(strSlice) {
			strSlice = append(strSlice, "?")
		}
		res = strSlice
	case trace.BYTES_T:
		var size uint32
		err = ebpfMsgDecoder.DecodeUint32(&size)
		if err != nil {
			return uint(argIdx), arg, errfmt.Errorf("error reading byte array size: %v", err)
		}
		// error if byte buffer is too big (and not a network event)
		if size > 4096 && (id < events.NetPacketBase || id > events.MaxNetID) {
			return uint(argIdx), arg, errfmt.Errorf("byte array size too big: %d", size)
		}
		res, err = ebpfMsgDecoder.ReadBytesLen(int(size))
	case trace.INT_ARR_2_T:
		var intArray [2]int32
		err = ebpfMsgDecoder.DecodeInt32Array(intArray[:], 2)
		if err != nil {
			return uint(argIdx), arg, errfmt.Errorf("error reading int elements: %v", err)
		}
		res = intArray
	case trace.UINT64_ARR_T:
		ulongArray := make([]uint64, 0)
		err := ebpfMsgDecoder.DecodeUint64Array(&ulongArray)
		if err != nil {
			return uint(argIdx), arg, errfmt.Errorf("error reading ulong elements: %v", err)
		}
		res = ulongArray
	case trace.TIMESPEC_T:
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
		return uint(argIdx), arg, errfmt.Errorf("error unknown arg type %v", decodeType)
	}
	if err != nil {
		return uint(argIdx), arg, errfmt.WrapError(err)
	}
	arg.Value = res
	return uint(argIdx), arg, nil
}

func GetDecodeType(fieldType string) trace.DecodeAs {
	switch fieldType {
	case "int":
		return trace.INT_T
	case "unsigned int":
		return trace.UINT_T
	case "long":
		return trace.LONG_T
	case "unsigned long":
		return trace.ULONG_T
	case "u16":
		return trace.U16_T
	case "u8":
		return trace.U8_T
	case "bool":
		return trace.BOOL_T
	case "void*":
		return trace.POINTER_T
	case "char*":
		return trace.STR_T
	case "const char*const*": // used by execve(at) argv and env
		return trace.STR_ARR_T
	case "const char**": // used by sched_process_exec argv and env
		return trace.ARGS_ARR_T
	case "struct sockaddr*":
		return trace.SOCK_ADDR_T
	case "bytes":
		return trace.BYTES_T
	case "[2]int32":
		return trace.INT_ARR_2_T
	case "slim_cred_t":
		return trace.CRED_T
	case "unsigned long[]", "[]trace.HookedSymbolData":
		return trace.UINT64_ARR_T
	case "struct timespec*":
		return trace.TIMESPEC_T
	default:
		// Default to pointer (printed as hex) for unsupported types
		return trace.POINTER_T
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
		socketDomainArg = parsers.AF_UNSPEC
	}
	res["sa_family"] = socketDomainArg.String()
	switch family {
	case 1: // AF_UNIX
		/*
			http://man7.org/linux/man-pages/man7/unix.7.html
			struct sockaddr_un {
					sa_family_t sun_family;     // AF_UNIX
					char        sun_path[108];  // Pathname
			};
		*/
		sunPath, err := readVarStringFromBuffer(ebpfMsgDecoder, 108)
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
		_, err := ebpfMsgDecoder.ReadBytesLen(8)
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
		addr, err := ebpfMsgDecoder.ReadBytesLen(16)
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

// readStringFromBuff reads strings from the event buffer using the following format:
//
// [32bit:string_size][string_size-1:byte_buffer][8bit:null_terminator]
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
	res, err := ebpfMsgDecoder.ReadBytesLen(int(size - 1)) // last byte is string terminating null
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

// readVarStringFromBuffer reads a null-terminated string from the ebpf buffer where the size is not
// known. The helper will read from the buffer char-by-char until it hits the null terminator
// or the given max length. The cursor will then skip to the point in the buffer after the max length.
func readVarStringFromBuffer(decoder *EbpfDecoder, max int) (string, error) {
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
	decoder.MoveCursor(max - count) // skip the cursor to the desired endpoint
	return string(res), nil
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

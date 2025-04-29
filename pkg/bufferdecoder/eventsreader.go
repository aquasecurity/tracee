package bufferdecoder

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/data"
	"github.com/aquasecurity/tracee/pkg/events/parsers"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/trace"
)

// readArgFromBuff read the next argument from the buffer.
// Return the index of the argument and the parsed argument.
func readArgFromBuff(
	id events.ID,
	ebpfMsgDecoder *EbpfDecoder,
	fields []events.DataField,
) (
	uint, trace.Argument, error,
) {
	var err error
	var decodedValue interface{}
	var argIdx uint8
	var arg trace.Argument

	err = ebpfMsgDecoder.DecodeUint8(&argIdx)
	if err != nil {
		return 0, arg, errfmt.Errorf("error reading arg index: %v", err)
	}
	if int(argIdx) >= len(fields) {
		return 0, arg, errfmt.Errorf("invalid arg index %d", argIdx)
	}
	dataField := fields[argIdx]
	arg.ArgMeta = dataField.ArgMeta
	decodeType := dataField.DecodeAs
	if decodeType == data.NONE_T {
		return 0, arg, errfmt.Errorf("arg \"%s\" from event %d: did not declare a decode type, this should not happen", arg.Name, id)
	}

	switch decodeType {
	case data.U8_T:
		var decodedData uint8
		err = ebpfMsgDecoder.DecodeUint8(&decodedData)
		decodedValue = decodedData
	case data.U16_T:
		var decodedData uint16
		err = ebpfMsgDecoder.DecodeUint16(&decodedData)
		decodedValue = decodedData
	case data.INT_T:
		var decodedData int32
		err = ebpfMsgDecoder.DecodeInt32(&decodedData)
		decodedValue = decodedData
	case data.UINT_T:
		var decodedData uint32
		err = ebpfMsgDecoder.DecodeUint32(&decodedData)
		decodedValue = decodedData
	case data.LONG_T:
		var decodedData int64
		err = ebpfMsgDecoder.DecodeInt64(&decodedData)
		decodedValue = decodedData
	case data.ULONG_T:
		var decodedData uint64
		err = ebpfMsgDecoder.DecodeUint64(&decodedData)
		decodedValue = decodedData
	case data.BOOL_T:
		var decodedData bool
		err = ebpfMsgDecoder.DecodeBool(&decodedData)
		decodedValue = decodedData
	case data.POINTER_T:
		var decodedData uint64
		err = ebpfMsgDecoder.DecodeUint64(&decodedData)
		decodedValue = trace.Pointer(decodedData)
	case data.SOCK_ADDR_T:
		decodedValue, err = readSockaddrFromBuff(ebpfMsgDecoder)
	case data.CRED_T:
		var decodedData SlimCred
		err = ebpfMsgDecoder.DecodeSlimCred(&decodedData)
		decodedValue = trace.SlimCred(decodedData) // here we cast to trace.SlimCred to ensure we send the public interface and not bufferdecoder.SlimCred
	case data.STR_T:
		decodedValue, err = readStringFromBuff(ebpfMsgDecoder)
	case data.STR_ARR_T:
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
		decodedValue = strSlice
	case data.ARGS_ARR_T:
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
		decodedValue = strSlice
	case data.BYTES_T:
		var size uint32
		err = ebpfMsgDecoder.DecodeUint32(&size)
		if err != nil {
			return uint(argIdx), arg, errfmt.Errorf("error reading byte array size: %v", err)
		}
		// error if byte buffer is too big (and not a network event)
		if size > 4096 && (id < events.NetPacketBase || id > events.MaxNetID) {
			return uint(argIdx), arg, errfmt.Errorf("byte array size too big: %d", size)
		}
		decodedValue, err = ebpfMsgDecoder.ReadBytesLen(int(size))
	case data.INT_ARR_2_T:
		var intArray [2]int32
		err = ebpfMsgDecoder.DecodeInt32Array(intArray[:], 2)
		if err != nil {
			return uint(argIdx), arg, errfmt.Errorf("error reading int elements: %v", err)
		}
		decodedValue = intArray
	case data.UINT64_ARR_T:
		ulongArray := make([]uint64, 0)
		err := ebpfMsgDecoder.DecodeUint64Array(&ulongArray)
		if err != nil {
			return uint(argIdx), arg, errfmt.Errorf("error reading ulong elements: %v", err)
		}
		decodedValue = ulongArray
	case data.TIMESPEC_T:
		var sec int64
		var nsec int64
		err = ebpfMsgDecoder.DecodeInt64(&sec)
		if err != nil {
			return uint(argIdx), arg, errfmt.WrapError(err)
		}
		err = ebpfMsgDecoder.DecodeInt64(&nsec)
		decodedValue = float64(sec) + (float64(nsec) / float64(1000000000))

	default:
		// if we don't recognize the arg type, we can't parse the rest of the buffer
		return uint(argIdx), arg, errfmt.Errorf("error unknown arg type %v", decodeType)
	}
	if err != nil {
		return uint(argIdx), arg, errfmt.WrapError(err)
	}

	// note(nadav.str): this allows defining data fields without an explicit type field - should we allow it?
	if decodeType.String() == arg.Type || arg.Type == "" {
		// identity case
		arg.Value = decodedValue
	} else {
		// present the decoded type
		presentor, ok := ebpfMsgDecoder.typeDecoder[decodeType][arg.Type]
		if !ok {
			return uint(argIdx), arg, errfmt.Errorf("failed to present decoded argument (decoding from type %s to presented type %s)", decodeType, arg.Type)
		}
		arg.Value, err = presentor(decodedValue)
		if err != nil {
			return uint(argIdx), arg, errfmt.WrapError(err)
		}
	}

	return uint(argIdx), arg, nil
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
		sunPath, err := readSunPathFromBuff(ebpfMsgDecoder, 108)
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

// readSunPathFromBuff reads a null-terminated string from the eBPF buffer, up to `max` bytes.
// Characters are read one by one until a NUL byte or the max limit is reached.
// If the first byte is NUL and the second is not, it's treated as an abstract socket and
// the first byte is replaced with '@'.
// After reading, the decoder cursor advances past `max` bytes in the buffer.
func readSunPathFromBuff(decoder *EbpfDecoder, max int) (string, error) {
	if max <= 0 {
		return "", errfmt.Errorf("max to decode sun_path must be greater than 0")
	}

	var err error
	var char int8
	res := make([]byte, 0, max)

	count := 0
	for i := 0; i < max; i++ {
		err = decoder.DecodeInt8(&char)
		if err != nil {
			return "", errfmt.Errorf("error reading sun_path at index %d out of %d: %v", i, max, err)
		}
		count++

		if char == 0 {
			// char as NUL may signal the end of the string or an abstract socket
			// https://elixir.bootlin.com/linux/v6.13.4/source/net/unix/af_unix.c#L72
			// https://man7.org/linux/man-pages/man7/unix.7.html
			if i > 0 {
				// NUL found after the first char means the end of the string
				break
			}
		}

		res = append(res, byte(char))
	}

	if res[0] == 0 {
		if len(res) == 1 {
			res = []byte{} // empty string
		} else {
			// abstract socket - res[0] = NUL && res[1] != NUL
			// https://elixir.bootlin.com/linux/v6.13.4/source/net/unix/af_unix.c#L3438
			res[0] = '@'
		}
	}

	decoder.MoveCursor(max - count) // move cursor to the desired endpoint
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

package tracee

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/aquasecurity/libbpfgo/helpers"
	"github.com/aquasecurity/tracee/pkg/external"
)

func readArgFromBuff(dataBuff io.Reader, params []external.ArgMeta) (external.ArgMeta, interface{}, error) {
	var err error
	var res interface{}
	var argIdx uint8
	var argMeta external.ArgMeta

	err = binary.Read(dataBuff, binary.LittleEndian, &argIdx)
	if err != nil {
		return argMeta, nil, fmt.Errorf("error reading arg index: %v", err)
	}
	if int(argIdx) >= len(params) {
		return argMeta, nil, fmt.Errorf("invalid arg index %d", argIdx)
	}
	argMeta = params[argIdx]
	argType := getParamType(argMeta.Type)

	switch argType {
	case u16T:
		var data uint16
		err = binary.Read(dataBuff, binary.LittleEndian, &data)
		res = data
	case intT:
		var data int32
		err = binary.Read(dataBuff, binary.LittleEndian, &data)
		res = data
	case uintT, devT, modeT:
		var data uint32
		err = binary.Read(dataBuff, binary.LittleEndian, &data)
		res = data
	case longT:
		var data int64
		err = binary.Read(dataBuff, binary.LittleEndian, &data)
		res = data
	case ulongT, offT, sizeT:
		var data uint64
		err = binary.Read(dataBuff, binary.LittleEndian, &data)
		res = data
	case pointerT:
		var data uint64
		err = binary.Read(dataBuff, binary.LittleEndian, &data)
		res = uintptr(data)
	case sockAddrT:
		res, err = readSockaddrFromBuff(dataBuff)
	case credT:
		var data external.SlimCred
		err = binary.Read(dataBuff, binary.LittleEndian, &data)
		res = data
	case strT:
		res, err = readStringFromBuff(dataBuff)
	case strArrT:
		var ss []string
		var arrLen uint8
		err = binary.Read(dataBuff, binary.LittleEndian, &arrLen)
		if err != nil {
			return argMeta, nil, fmt.Errorf("error reading string array number of elements: %v", err)
		}
		for i := 0; i < int(arrLen); i++ {
			s, err := readStringFromBuff(dataBuff)
			if err != nil {
				return argMeta, nil, fmt.Errorf("error reading string element: %v", err)
			}
			ss = append(ss, s)
		}
		res = ss
	case argsArrT:
		var ss []string
		var arrLen uint32
		var argNum uint32
		err = binary.Read(dataBuff, binary.LittleEndian, &arrLen)
		if err != nil {
			return argMeta, nil, fmt.Errorf("error reading args array length: %v", err)
		}
		err = binary.Read(dataBuff, binary.LittleEndian, &argNum)
		if err != nil {
			return argMeta, nil, fmt.Errorf("error reading args number: %v", err)
		}
		resBytes, err := readByteSliceFromBuff(dataBuff, int(arrLen))
		if err != nil {
			return argMeta, nil, fmt.Errorf("error reading args array: %v", err)
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
		err = binary.Read(dataBuff, binary.LittleEndian, &size)
		if err != nil {
			return argMeta, nil, fmt.Errorf("error reading byte array size: %v", err)
		}
		if size > 4096 {
			return argMeta, nil, fmt.Errorf("byte array size too big: %d", size)
		}
		res, err = readByteSliceFromBuff(dataBuff, int(size))
	case intArr2T:
		var intArray [2]int32
		err = binary.Read(dataBuff, binary.LittleEndian, &intArray)
		if err != nil {
			return argMeta, nil, fmt.Errorf("error reading int elements: %v", err)
		}
		res = intArray
	default:
		// if we don't recognize the arg type, we can't parse the rest of the buffer
		return argMeta, nil, fmt.Errorf("error unknown arg type %v", argType)
	}
	if err != nil {
		return argMeta, nil, err
	}
	return argMeta, res, nil
}

func readSockaddrFromBuff(buff io.Reader) (map[string]string, error) {
	res := make(map[string]string, 5)
	var family int16
	err := binary.Read(buff, binary.LittleEndian, &family)
	if err != nil {
		return nil, err
	}
	res["sa_family"] = helpers.ParseSocketDomain(uint32(family))
	switch family {
	case 1: // AF_UNIX
		/*
			http://man7.org/linux/man-pages/man7/unix.7.html
			struct sockaddr_un {
					sa_family_t sun_family;     // AF_UNIX
					char        sun_path[108];  // Pathname
			};
		*/
		var sunPathBuf [108]byte
		err := binary.Read(buff, binary.LittleEndian, &sunPathBuf)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_un: %v", err)
		}
		trimmedPath := bytes.TrimLeft(sunPathBuf[:], "\000")
		sunPath := ""
		if len(trimmedPath) != 0 {
			sunPath, err = readStringVarFromBuff(bytes.NewBuffer(trimmedPath), 108)
		}
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_un: %v", err)
		}
		res["sun_path"] = sunPath
	case 2: // AF_INET
		/*
			http://man7.org/linux/man-pages/man7/ip.7.html
			struct sockaddr_in {
				sa_family_t    sin_family; // address family: AF_INET
				in_port_t      sin_port;   // port in network byte order
				struct in_addr sin_addr;   // internet address
				// byte        padding[8]; //https://elixir.bootlin.com/linux/v4.20.17/source/include/uapi/linux/in.h#L232
			};
			struct in_addr {
				uint32_t       s_addr;     // address in network byte order
			};
		*/
		var port uint16
		err = binary.Read(buff, binary.BigEndian, &port)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in: %v", err)
		}
		res["sin_port"] = strconv.Itoa(int(port))
		var addr uint32
		err = binary.Read(buff, binary.BigEndian, &addr)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in: %v", err)
		}
		res["sin_addr"] = PrintUint32IP(addr)
		_, err := readByteSliceFromBuff(buff, 8)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in: %v", err)
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
		err = binary.Read(buff, binary.BigEndian, &port)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in6: %v", err)
		}
		res["sin6_port"] = strconv.Itoa(int(port))

		var flowinfo uint32
		err = binary.Read(buff, binary.BigEndian, &flowinfo)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in6: %v", err)
		}
		res["sin6_flowinfo"] = strconv.Itoa(int(flowinfo))
		addr, err := readByteSliceFromBuff(buff, 16)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in6: %v", err)
		}
		res["sin6_addr"] = Print16BytesSliceIP(addr)
		var scopeid uint32
		err = binary.Read(buff, binary.BigEndian, &scopeid)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in6: %v", err)
		}
		res["sin6_scopeid"] = strconv.Itoa(int(scopeid))
	}
	return res, nil
}

func readStringFromBuff(buff io.Reader) (string, error) {
	var err error
	var size uint32
	err = binary.Read(buff, binary.LittleEndian, &size)
	if err != nil {
		return "", fmt.Errorf("error reading string size: %v", err)
	}
	if size > 4096 {
		return "", fmt.Errorf("string size too big: %d", size)
	}
	res, err := readByteSliceFromBuff(buff, int(size-1)) //last byte is string terminating null
	defer func() {
		var dummy int8
		binary.Read(buff, binary.LittleEndian, &dummy) //discard last byte which is string terminating null
	}()
	if err != nil {
		return "", fmt.Errorf("error reading string arg: %v", err)
	}
	return string(res), nil
}

// readStringVarFromBuff reads a null-terminated string from `buff`
// max length can be passed as `max` to optimize memory allocation, otherwise pass 0
func readStringVarFromBuff(buff io.Reader, max int) (string, error) {
	var err error
	var char int8
	res := make([]byte, max)
	err = binary.Read(buff, binary.LittleEndian, &char)
	if err != nil {
		return "", fmt.Errorf("error reading null terminated string: %v", err)
	}
	for count := 1; char != 0 && count < max; count++ {
		res = append(res, byte(char))
		err = binary.Read(buff, binary.LittleEndian, &char)
		if err != nil {
			return "", fmt.Errorf("error reading null terminated string: %v", err)
		}
	}
	res = bytes.TrimLeft(res[:], "\000")
	return string(res), nil
}

func readByteSliceFromBuff(buff io.Reader, len int) ([]byte, error) {
	var err error
	res := make([]byte, len)
	err = binary.Read(buff, binary.LittleEndian, &res)
	if err != nil {
		return nil, fmt.Errorf("error reading byte array: %v", err)
	}
	return res, nil
}

package tracee_engine

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/aquasecurity/tracee/tracee-ebpf/engine/consts"
	"github.com/aquasecurity/tracee/tracee-ebpf/engine/event"
	"io"
	"net"
	"strconv"
	"sync"

	"github.com/aquasecurity/libbpfgo/helpers"
)

// alert struct encodes a security alert message with a timestamp
// it is used to unmarshal binary data and therefore should match (bit by bit) to the `alert_t` struct in the ebpf code.
type alert struct {
	Ts      uint64
	Msg     uint32
	Payload uint8
}

// printAlert prints the encoded alert message and output file path if required
func printAlert(alert alert) string {
	var res string

	var securityAlerts = map[uint32]string{
		1: "Mmaped region with W+E permissions!",
		2: "Protection changed to Executable!",
		3: "Protection changed from E to W+E!",
		4: "Protection changed from W+E to E!",
	}

	if msg, ok := securityAlerts[alert.Msg]; ok {
		res = msg
	} else {
		res = strconv.Itoa(int(alert.Msg))
	}

	if alert.Payload != 0 {
		res += " Saving data to bin." + strconv.Itoa(int(alert.Ts))
	}

	return res
}

func readArgFromBuff(dataBuff io.Reader) (consts.ArgTag, interface{}, error) {
	var err error
	var res interface{}
	var argTag consts.ArgTag
	var argType consts.ArgType
	err = binary.Read(dataBuff, binary.LittleEndian, &argType)
	if err != nil {
		return argTag, nil, fmt.Errorf("error reading arg type: %v", err)
	}
	err = binary.Read(dataBuff, binary.LittleEndian, &argTag)
	if err != nil {
		return argTag, nil, fmt.Errorf("error reading arg tag: %v", err)
	}
	switch argType {
	case consts.U16T:
		var data uint16
		err = binary.Read(dataBuff, binary.LittleEndian, &data)
		res = data
	case consts.IntT:
		var data int32
		err = binary.Read(dataBuff, binary.LittleEndian, &data)
		res = data
	case consts.UintT, consts.DevT, consts.ModeT:
		var data uint32
		err = binary.Read(dataBuff, binary.LittleEndian, &data)
		res = data
	case consts.LongT:
		var data int64
		err = binary.Read(dataBuff, binary.LittleEndian, &data)
		res = data
	case consts.UlongT, consts.OffT, consts.SizeT:
		var data uint64
		err = binary.Read(dataBuff, binary.LittleEndian, &data)
		res = data
	case consts.PointerT:
		var data uint64
		err = binary.Read(dataBuff, binary.LittleEndian, &data)
		res = uintptr(data)
	case consts.SockAddrT:
		res, err = readSockaddrFromBuff(dataBuff)
	case consts.AlertT:
		var data alert
		err = binary.Read(dataBuff, binary.LittleEndian, &data)
		res = data
	case consts.CredT:
		var data event.SlimCred
		err = binary.Read(dataBuff, binary.LittleEndian, &data)
		res = data
	case consts.StrT:
		res, err = readStringFromBuff(dataBuff)
	case consts.StrArrT:
		var ss []string
		var arrLen uint8
		err = binary.Read(dataBuff, binary.LittleEndian, &arrLen)
		if err != nil {
			return argTag, nil, fmt.Errorf("error reading string array number of elements: %v", err)
		}
		for i := 0; i < int(arrLen); i++ {
			s, err := readStringFromBuff(dataBuff)
			if err != nil {
				return argTag, nil, fmt.Errorf("error reading string element: %v", err)
			}
			ss = append(ss, s)
		}
		res = ss
	case consts.BytesT:
		var size uint32
		err = binary.Read(dataBuff, binary.LittleEndian, &size)
		if err != nil {
			return argTag, nil, fmt.Errorf("error reading byte array size: %v", err)
		}
		if size > 4096 {
			return argTag, nil, fmt.Errorf("byte array size too big: %d", size)
		}
		res, err = readByteSliceFromBuff(dataBuff, int(size))
	default:
		// if we don't recognize the arg type, we can't parse the rest of the buffer
		return argTag, nil, fmt.Errorf("error unknown arg type %v", argType)
	}
	if err != nil {
		return argTag, nil, err
	}
	return argTag, res, nil
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

// mergeErrors merges multiple channels of errors.
// Based on https://blog.golang.org/pipelines.
func mergeErrors(cs ...<-chan error) <-chan error {
	var wg sync.WaitGroup
	// We must ensure that the output channel has the capacity to hold as many errors
	// as there are error channels. This will ensure that it never blocks, even
	// if WaitForPipeline returns early.
	out := make(chan error, len(cs))

	// Start an output goroutine for each input channel in cs.  output
	// copies values from c to out until c is closed, then calls wg.Done.
	output := func(c <-chan error) {
		for n := range c {
			out <- n
		}
		wg.Done()
	}
	wg.Add(len(cs))
	for _, c := range cs {
		go output(c)
	}

	// Start a goroutine to close out once all the output goroutines are
	// done.  This must start after the wg.Add call.
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

// print16BytesSliceIP prints the IP address encoded as 16 bytes long PrintBytesSliceIP
// It would be more correct to accept a [16]byte instead of variable lenth slice, but that would case unnecessary memory copying and type conversions
func print16BytesSliceIP(in []byte) string {
	ip := net.IP(in)
	return ip.String()
}

func readSockaddrFromBuff(buff io.Reader) (map[string]string, error) {
	res := make(map[string]string, 3)
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
		res["sin_addr"] = printUint32IP(addr)
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
		res["sin6_addr"] = print16BytesSliceIP(addr)
		var scopeid uint32
		err = binary.Read(buff, binary.BigEndian, &scopeid)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in6: %v", err)
		}
		res["sin6_scopeid"] = strconv.Itoa(int(scopeid))
	}
	return res, nil
}

// printUint32IP prints the IP address encoded as a uint32
func printUint32IP(in uint32) string {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, in)
	return ip.String()
}

func boolToUInt32(b bool) uint32 {
	if b {
		return uint32(1)
	}
	return uint32(0)
}

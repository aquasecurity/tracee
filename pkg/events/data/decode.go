package data

// DecodeAs is an enum that encodes the argument types that an
// eBPF program may write to the shared buffer. In practice they designate
// either/or a type which is specifically encoded as an argument type in eBPF
// or a strategy of passing an argument on the submission buffer via some
// function.
type DecodeAs uint16

// The types of this section in particular are those possibly submitted in
// syscall events. Therefore, these should match to the type enum and table in:
// pkg/ebpf/c/types.h and buffer.h respectively.
const (
	NONE_T DecodeAs = iota // Default value - the argument does not originate from a decodable buffer.
	INT_T
	UINT_T
	LONG_T
	ULONG_T
	U16_T
	U8_T
	INT_ARR_2_T
	UINT64_ARR_T
	POINTER_T
	BYTES_T
	STR_T
	STR_ARR_T
	SOCK_ADDR_T
	CRED_T
	TIMESPEC_T
)

// These types are in a separate section since they are not defined as enums in the ebpf code.
// That is because they are unused by syscalls.
// Instead, they designate a functional submission strategy.
// (ie. ARGS_ARR_T is submitted by the strategy defined in buffer.h:save_args_str_arr_to_buf).
const (
	ARGS_ARR_T DecodeAs = iota + 64
	BOOL_T
	FLOAT_T
	FLOAT64_T
	MAX_TRACEE_DECODES
)

// The maximum value for decode types is 0xFF.
// The values from 0x80 to 0xFF are reserved for user defined decode types.
// This is to allow users to define their own decode types in their own ebpf programs.
// The values from 0x00 to 0x7F are reserved for tracee.
const (
	USER_DEFINED_DECODE_BEGIN DecodeAs = 128
	USER_DEFINED_DECODE_END   DecodeAs = 255
)

var decodeAsStringDict = map[DecodeAs]string{
	NONE_T:       "nil",
	INT_T:        "int32",
	UINT_T:       "uint32",
	LONG_T:       "int64",
	ULONG_T:      "uint64",
	U16_T:        "uint16",
	U8_T:         "uint8",
	INT_ARR_2_T:  "[2]int",
	UINT64_ARR_T: "[]uint64",
	POINTER_T:    "trace.Pointer",
	BYTES_T:      "[]byte",
	STR_T:        "string",
	STR_ARR_T:    "[]string",
	SOCK_ADDR_T:  "SockAddr",
	CRED_T:       "trace.SlimCred",
	TIMESPEC_T:   "float64",
	ARGS_ARR_T:   "[]string",
	BOOL_T:       "bool",
	FLOAT_T:      "float",
	FLOAT64_T:    "float64",
}

func (d DecodeAs) String() string {
	// in the future register into the dictionary along decode strategies
	s, ok := decodeAsStringDict[d]
	if !ok {
		return "nil"
	}
	return s
}

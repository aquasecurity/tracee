package ebpf

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unsafe"

	"github.com/aquasecurity/tracee/pkg/logger"
)

const BPFMaxErrFileLen = 72 // BPF_MAX_ERR_FILE_LEN

type BPFErrorType uint32

const (
	BPFErrUnspec BPFErrorType = iota // BPF_ERR_UNSPEC

	// tracee functions
	BPFErrInitContext // BPF_ERR_INIT_CONTEXT

	// bpf helpers functions
	BPFErrMapUpdateElem  // BPF_ERR_MAP_UPDATE_ELEM
	BPFErrMapDeleteElem  // BPF_ERR_MAP_DELETE_ELEM
	BPFErrGetCurrentComm // BPF_ERR_GET_CURRENT_COMM
	BPFErrTailCall       // BPF_ERR_TAIL_CALL
)

var stringMap = map[BPFErrorType]string{
	BPFErrUnspec: "BPF_ERR_UNSPEC",

	// tracee functions
	BPFErrInitContext: "BPF_ERR_INIT_CONTEXT",

	// bpf helpers functions
	BPFErrMapUpdateElem:  "BPF_ERR_MAP_UPDATE_ELEM",
	BPFErrMapDeleteElem:  "BPF_ERR_MAP_DELETE_ELEM",
	BPFErrGetCurrentComm: "BPF_ERR_GET_CURRENT_COMM",
	BPFErrTailCall:       "BPF_ERR_TAIL_CALL",
}

var errorMap = map[BPFErrorType]string{
	BPFErrUnspec: "Unspecifed BPF error",

	// tracee functions
	BPFErrInitContext: "Failed to init context",

	// bpf helpers functions
	BPFErrMapUpdateElem:  "Failed to add or update a map element",
	BPFErrMapDeleteElem:  "Failed to delete a map element",
	BPFErrGetCurrentComm: "Failed to get current command",
	BPFErrTailCall:       "Failed to tail call",
}

func (b BPFErrorType) String() string {
	if bpfErr, found := stringMap[b]; found {
		return bpfErr
	}

	return stringMap[BPFErrUnspec]
}

// BPFError struct contains aggregated data about a bpf error origin
type BPFError struct {
	id       BPFErrorType
	logLevel logger.Level
	count    uint32                 // percpu error occurrences
	padding  uint32                 // empty space
	ret      int64                  // return value
	cpu      uint32                 // cpu number
	line     uint32                 // line number
	file     [BPFMaxErrFileLen]byte // filename
}

func (b BPFError) Error() string {
	if bpfErr, found := errorMap[BPFErrorType(b.id)]; found {
		return bpfErr
	}

	return errorMap[BPFErrUnspec]
}

func (b BPFError) ID() uint32 {
	return uint32(b.id)
}

func (b BPFError) Type() BPFErrorType {
	return BPFErrorType(b.id)
}

func (b BPFError) LogLevel() logger.Level {
	return b.logLevel
}

func (b BPFError) Count() uint32 {
	return b.count
}

func (b BPFError) Return() int64 {
	return int64(b.ret)
}

func (b BPFError) CPU() uint32 {
	return b.cpu
}

func (b BPFError) Line() uint32 {
	return b.line
}

func (b BPFError) File() []byte {
	return b.file[:]
}

func (b BPFError) FileAsString() string {
	errFile := string(b.file[:])
	errFileEnd := strings.Index(errFile, "\x00")

	return errFile[:errFileEnd]
}

func (b BPFError) Size() int {
	return int(unsafe.Sizeof(b.id)) +
		int(unsafe.Sizeof(b.logLevel)) +
		int(unsafe.Sizeof(b.count)) +
		int(unsafe.Sizeof(b.padding)) +
		int(unsafe.Sizeof(b.ret)) +
		int(unsafe.Sizeof(b.id)) +
		int(unsafe.Sizeof(b.cpu)) +
		int(unsafe.Sizeof(b.line)) +
		int(len(b.file))
}

func (b *BPFError) Decode(rawBuffer []byte) error {
	if len(rawBuffer) < b.Size() {
		return fmt.Errorf("can't decode error raw data - buffer of %d should have at least %d bytes", len(rawBuffer), b.Size())
	}

	b.id = BPFErrorType(binary.LittleEndian.Uint32(rawBuffer[0:4]))
	b.logLevel = logger.Level(binary.LittleEndian.Uint32(rawBuffer[4:8])) // this is an int8 (zapcore.Level)
	b.count = binary.LittleEndian.Uint32(rawBuffer[8:12])
	b.padding = binary.LittleEndian.Uint32(rawBuffer[12:16])

	// bpf_error
	b.ret = int64(binary.LittleEndian.Uint64(rawBuffer[16:24]))
	b.cpu = binary.LittleEndian.Uint32(rawBuffer[24:28])
	b.line = binary.LittleEndian.Uint32(rawBuffer[28:32])
	copy(b.file[:], rawBuffer[32:104])
	// bpf_error

	return nil
}

func (t *Tracee) processBPFErrors() {
	for {
		select {
		case rawData := <-t.bpfErrorsChannel:
			if len(rawData) == 0 {
				continue
			}

			bpfErr := BPFError{}
			if err := bpfErr.Decode(rawData); err != nil {
				t.handleError(fmt.Errorf("consumeBPFErrorsChannel: decode - %v", err))
				continue
			}
			// This logger timestamp in no way reflects the ebpf error original time
			// since bpf errors channel is populated with aggregated logs
			logger.BPFError(bpfErr.Error(), logger.Level(bpfErr.LogLevel()),
				"id", bpfErr.ID(),
				"type", bpfErr.Type().String(),
				"ret", bpfErr.Return(),
				"cpu", bpfErr.CPU(),
				"file", bpfErr.FileAsString(),
				"line", bpfErr.Line(),
				"count", bpfErr.Count(),
			)
			t.stats.BPFErrorsCount.Increment(uint64(bpfErr.Count()))

		case lost := <-t.lostBPFErrChannel:
			// When terminating tracee-ebpf the lost channel receives multiple "0 lost events" events.
			// This check prevents those 0 lost events messages to be written to stderr until the bug is fixed:
			// https://github.com/aquasecurity/libbpfgo/issues/122
			if lost > 0 {
				t.stats.LostBPFErrCount.Increment(lost)
				logger.Warn(fmt.Sprintf("lost %d ebpf error events", lost))
			}
		}
	}
}

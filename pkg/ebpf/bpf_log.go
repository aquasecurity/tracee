package ebpf

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"unsafe"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
)

const BPFMaxLogFileLen = 72 // BPF_MAX_LOG_FILE_LEN

type BPFLogType uint32

const (
	BPFLogIDUnspec BPFLogType = iota // BPF_LOG_ID_UNSPEC

	// tracee functions
	BPFLogIDInitContext // BPF_LOG_ID_INIT_CONTEXT

	// bpf helpers functions
	BPFLogIDMapLookupElem  // BPF_LOG_ID_MAP_LOOKUP_ELEM
	BPFLogIDMapUpdateElem  // BPF_LOG_ID_MAP_UPDATE_ELEM
	BPFLogIDMapDeleteElem  // BPF_LOG_ID_MAP_DELETE_ELEM
	BPFLogIDGetCurrentComm // BPF_LOG_ID_GET_CURRENT_COMM
	BPFLogIDTailCall       // BPF_LOG_ID_TAIL_CALL
	BPFLogIDMemRead        // BPF_LOG_ID_MEM_READ

	// hidden kernel module functions
	BPFLogIDHidKerMod
)

var stringMap = map[BPFLogType]string{
	BPFLogIDUnspec: "BPF_LOG_ID_UNSPEC",

	// tracee functions
	BPFLogIDInitContext: "BPF_LOG_ID_INIT_CONTEXT",

	// bpf helpers functions
	BPFLogIDMapLookupElem:  "BPF_LOG_ID_MAP_LOOKUP_ELEM",
	BPFLogIDMapUpdateElem:  "BPF_LOG_ID_MAP_UPDATE_ELEM",
	BPFLogIDMapDeleteElem:  "BPF_LOG_ID_MAP_DELETE_ELEM",
	BPFLogIDGetCurrentComm: "BPF_LOG_ID_GET_CURRENT_COMM",
	BPFLogIDTailCall:       "BPF_LOG_ID_TAIL_CALL",
	BPFLogIDMemRead:        "BPF_LOG_ID_MEM_READ",

	// hidden kernel module functions
	BPFLogIDHidKerMod: "BPF_LOG_ID_HID_KER_MOD",
}

var errorMap = map[BPFLogType]string{
	BPFLogIDUnspec: "Unspecifed BPF log",

	// tracee functions
	BPFLogIDInitContext: "Failed to init context",

	// bpf helpers functions
	BPFLogIDMapLookupElem:  "Failed to find a map element",
	BPFLogIDMapUpdateElem:  "Failed to add or update a map element",
	BPFLogIDMapDeleteElem:  "Failed to delete a map element",
	BPFLogIDGetCurrentComm: "Failed to get current command",
	BPFLogIDTailCall:       "Failed to tail call",
	BPFLogIDMemRead:        "Failed to read memory",

	// hidden kernel module functions
	BPFLogIDHidKerMod: "Failure in hidden kernel module seeker logic",
}

func (b BPFLogType) String() string {
	if bpfLog, found := stringMap[b]; found {
		return bpfLog
	}

	return stringMap[BPFLogIDUnspec]
}

// BPFLog struct contains aggregated data about a bpf log origin
type BPFLog struct {
	id       BPFLogType
	logLevel logger.Level
	count    uint32                 // percpu log occurrences
	padding  uint32                 // empty space
	ret      int64                  // return value
	cpu      uint32                 // cpu number
	line     uint32                 // line number
	file     [BPFMaxLogFileLen]byte // filename
}

func (b BPFLog) Error() string {
	if bpfLog, found := errorMap[BPFLogType(b.id)]; found {
		return bpfLog
	}

	return errorMap[BPFLogIDUnspec]
}

func (b BPFLog) ID() uint32 {
	return uint32(b.id)
}

func (b BPFLog) Type() BPFLogType {
	return BPFLogType(b.id)
}

func (b BPFLog) LogLevel() logger.Level {
	return b.logLevel
}

func (b BPFLog) Count() uint32 {
	return b.count
}

func (b BPFLog) Return() int64 {
	return int64(b.ret)
}

func (b BPFLog) CPU() uint32 {
	return b.cpu
}

func (b BPFLog) Line() uint32 {
	return b.line
}

func (b BPFLog) File() []byte {
	return b.file[:]
}

func (b BPFLog) FileAsString() string {
	logFile := string(b.file[:])
	logFileEnd := strings.Index(logFile, "\x00")

	return logFile[:logFileEnd]
}

func (b BPFLog) Size() int {
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

func (b *BPFLog) Decode(rawBuffer []byte) error {
	if len(rawBuffer) < b.Size() {
		return errfmt.Errorf("can't decode log raw data - buffer of %d should have at least %d bytes", len(rawBuffer), b.Size())
	}

	b.id = BPFLogType(binary.LittleEndian.Uint32(rawBuffer[0:4]))
	b.logLevel = logger.Level(binary.LittleEndian.Uint32(rawBuffer[4:8])) // this is an int8 (zapcore.Level)
	b.count = binary.LittleEndian.Uint32(rawBuffer[8:12])
	b.padding = binary.LittleEndian.Uint32(rawBuffer[12:16])

	// bpf_log
	b.ret = int64(binary.LittleEndian.Uint64(rawBuffer[16:24]))
	b.cpu = binary.LittleEndian.Uint32(rawBuffer[24:28])
	b.line = binary.LittleEndian.Uint32(rawBuffer[28:32])
	copy(b.file[:], rawBuffer[32:104])
	// bpf_log

	return nil
}

func (t *Tracee) processBPFLogs(ctx context.Context) {
	logger.Debugw("Starting processBPFLogs goroutine")
	defer logger.Debugw("Stopped processBPFLogs goroutine")

	for {
		select {
		case rawData := <-t.bpfLogsChannel:
			if len(rawData) == 0 {
				continue
			}

			bpfLog := BPFLog{}
			if err := bpfLog.Decode(rawData); err != nil {
				t.handleError(errfmt.Errorf("consume BPFLogsChannel: decode - %v", err))
				continue
			}
			// This logger timestamp in no way reflects the bpf log original time
			// since bpf logs channel is populated with aggregated logs
			logger.Log(logger.Level(bpfLog.LogLevel()), false,
				bpfLog.Error(),
				"id", bpfLog.ID(),
				"type", bpfLog.Type().String(),
				"ret", bpfLog.Return(),
				"cpu", bpfLog.CPU(),
				"file", bpfLog.FileAsString(),
				"line", bpfLog.Line(),
				"count", bpfLog.Count(),
			)
			if err := t.stats.BPFLogsCount.Increment(uint64(bpfLog.Count())); err != nil {
				logger.Errorw("Incrementing BPF logs count", "error", err)
			}

		case lost := <-t.lostBPFLogChannel:
			if err := t.stats.LostBPFLogsCount.Increment(lost); err != nil {
				logger.Errorw("Incrementing lost BPF logs count", "error", err)
			}
			logger.Warnw(fmt.Sprintf("Lost %d ebpf logs events", lost))

		case <-ctx.Done():
			return
		}
	}
}

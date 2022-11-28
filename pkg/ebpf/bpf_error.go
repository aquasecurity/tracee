package ebpf

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"time"
	"unsafe"

	"github.com/aquasecurity/tracee/pkg/logger"
)

const BPF_MAX_ERR_FILE_LEN = 72

type BPFErrorType uint32

const (
	BPF_ERR_UNSPEC BPFErrorType = iota

	BPF_ERR_MAP_UPDATE_ELEM
	BPF_ERR_MAP_DELETE_ELEM
	BPF_ERR_GET_CURRENT_COMM
	BPF_ERR_TAIL_CALL
)

var stringMap = map[BPFErrorType]string{
	BPF_ERR_UNSPEC: "BPF_ERR_UNSPEC",

	BPF_ERR_MAP_UPDATE_ELEM:  "BPF_ERR_MAP_UPDATE_ELEM",
	BPF_ERR_MAP_DELETE_ELEM:  "BPF_ERR_MAP_DELETE_ELEM",
	BPF_ERR_GET_CURRENT_COMM: "BPF_ERR_GET_CURRENT_COMM",
	BPF_ERR_TAIL_CALL:        "BPF_ERR_TAIL_CALL",
}

var errorMap = map[BPFErrorType]string{
	BPF_ERR_UNSPEC: "Unspecifed BPF error",

	BPF_ERR_MAP_UPDATE_ELEM:  "Failed to add or update a map element",
	BPF_ERR_MAP_DELETE_ELEM:  "Failed to delete a map element",
	BPF_ERR_GET_CURRENT_COMM: "Failed to get current command",
	BPF_ERR_TAIL_CALL:        "Failed to tail call",
}

func (b BPFErrorType) String() string {
	if bpfErr, found := stringMap[b]; found {
		return bpfErr
	}

	return stringMap[BPF_ERR_UNSPEC]
}

type BPFError struct {
	ret  int64
	id   uint32
	line uint32
	file [BPF_MAX_ERR_FILE_LEN]byte
}

func (b BPFError) Error() string {
	if bpfErr, found := errorMap[BPFErrorType(b.id)]; found {
		return bpfErr
	}

	return errorMap[BPF_ERR_UNSPEC]
}

func (b BPFError) Return() int64 {
	return int64(b.ret)
}

func (b BPFError) ID() uint32 {
	return uint32(b.id)
}

func (b BPFError) Type() BPFErrorType {
	return BPFErrorType(b.id)
}

func (b BPFError) Line() uint32 {
	return b.line
}

func (b BPFError) File() []byte {
	return b.file[:]
}

func (b BPFError) FileAsString() string {
	errFunc := string(b.file[:])
	errFuncEnd := strings.Index(errFunc, "\x00")

	return errFunc[:errFuncEnd]
}

func (b BPFError) Size() int {
	return int(unsafe.Sizeof(b.ret)) +
		int(unsafe.Sizeof(b.id)) +
		int(unsafe.Sizeof(b.line)) +
		int(len(b.file))
}

func (b *BPFError) Decode(rawBuffer []byte) error {
	if len(rawBuffer) < b.Size() {
		return fmt.Errorf("can't decode error raw data - buffer of %d should be of %d bytes", len(rawBuffer), b.Size())
	}

	b.ret = int64(binary.LittleEndian.Uint64(rawBuffer[0:8]))
	b.id = binary.LittleEndian.Uint32(rawBuffer[8:12])
	b.line = binary.LittleEndian.Uint32(rawBuffer[12:16])
	copy(b.file[:], rawBuffer[16:88])

	return nil
}

func addUint32(a, b uint32) (uint32, error) {
	sum := a + b
	if sum < a {
		return sum, fmt.Errorf("sum wraped to %v", sum)
	}

	return sum, nil
}

// dumpErrorCounts logs error counts at each time interval
func dumpErrorCounts(t *Tracee) {
	ticker := time.NewTicker(time.Second * t.config.Output.AggregateBPFErrorsInterval)
	for range ticker.C {
		totalCount := uint32(0)
		var addErr error
		iter := t.BPFErrorsCountMap.Iterator()
		for iter.Next() {
			keyBytes := iter.Key()
			bpfErr := BPFError{}
			if err := bpfErr.Decode(keyBytes); err != nil {
				t.handleError(fmt.Errorf("dumpErrorCounts - %v", err))
				continue
			}

			value, err := t.BPFErrorsCountMap.GetValue(unsafe.Pointer(&keyBytes[0]))
			if err != nil {
				t.handleError(fmt.Errorf("dumpErrorCounts - %v", err))
				continue
			}

			count := binary.LittleEndian.Uint32(value)
			logger.Error(bpfErr.Error(),
				"id", bpfErr.ID(),
				"type", bpfErr.Type().String(),
				"ret", bpfErr.Return(),
				"file", bpfErr.FileAsString(),
				"line", bpfErr.Line(),
				"count", count,
			)
			totalCount, addErr = addUint32(totalCount, count)
			if addErr != nil {
				t.handleError(fmt.Errorf("dumpErrorCounts - %v", addErr))
			}
		}
		if err := iter.Err(); err != nil {
			t.handleError(fmt.Errorf("dumpErrorCounts - %v", err))
			continue
		}
		// This increment is a snapshot built over multiple map lookups, so error counts in kernel space
		// possibly changes during the process as we have no lock for userspace iteration.
		increment := totalCount - uint32(t.stats.BPFErrorsCount.Read())
		// this check can be moved to Counter
		if uint32(math.MaxInt32-t.stats.BPFErrorsCount.Read()) < increment {
			t.handleError(fmt.Errorf("dumpErrorCounts - BPFErrorsCount.Increment overflow"))
		}
		t.stats.BPFErrorsCount.Increment(int(increment))
	}
}

// consumeBPFErrorsChannel logs every bpf error occurrence
func consumeBPFErrorsChannel(t *Tracee) {
	for {
		select {
		case rawData := <-t.bpfErrorsChannel:
			if len(rawData) == 0 {
				continue
			}

			bpfErr := BPFError{}
			if err := bpfErr.Decode(rawData); err != nil {
				t.handleError(fmt.Errorf("consumeBPFErrorsChannel - %v", err))
				continue
			}

			logger.Error(bpfErr.Error(),
				"id", bpfErr.ID(),
				"type", bpfErr.Type().String(),
				"ret", bpfErr.Return(),
				"file", bpfErr.FileAsString(),
				"line", bpfErr.Line(),
			)
			t.stats.BPFErrorsCount.Increment()

		case lost := <-t.lostBPFErrChannel:
			// When terminating tracee-ebpf the lost channel receives multiple "0 lost events" events.
			// This check prevents those 0 lost events messages to be written to stderr until the bug is fixed:
			// https://github.com/aquasecurity/libbpfgo/issues/122
			if lost > 0 {
				t.stats.LostBPFErrCount.Increment(int(lost))
				t.config.ChanErrors <- fmt.Errorf("lost %d ebpf error events", lost)
			}
		}
	}
}

func (t *Tracee) processBPFErrors() {
	if t.config.Output.AggregateBPFErrors {
		dumpErrorCounts(t)
	} else {
		consumeBPFErrorsChannel(t)
	}
}

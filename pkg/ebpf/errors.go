package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/aquasecurity/tracee/pkg/logger"
)

func (t *Tracee) processEBPFErrors() {
	for {
		select {
		case dataRaw := <-t.ebpfErrorsChannel:
			if len(dataRaw) == 0 {
				continue
			}

			var errorRet int64
			var errorMsg string
			errorRetSize := int(unsafe.Sizeof(errorRet))

			if len(dataRaw) >= errorRetSize {
				errorRet = int64(binary.LittleEndian.Uint64(dataRaw[:errorRetSize]))
			} else {
				t.handleError(fmt.Errorf("can't read error from buffer: buffer too short"))
				continue
			}

			// message is optional
			if len(dataRaw) > errorRetSize {
				errorMsg = string(bytes.Trim(dataRaw[errorRetSize:], "\x00"))
			}

			var logKeyValues []interface{}
			logKeyValues = append(logKeyValues, "return", errorRet)
			if len(errorMsg) > 0 {
				logKeyValues = append(logKeyValues, "message", errorMsg)
			}
			logger.Error("ebpf", logKeyValues...)
			t.stats.EBPFErrorsCount.Increment()

		case lost := <-t.lostEBPFErrChannel:
			// When terminating tracee-ebpf the lost channel receives multiple "0 lost events" events.
			// This check prevents those 0 lost events messages to be written to stderr until the bug is fixed:
			// https://github.com/aquasecurity/libbpfgo/issues/122
			if lost > 0 {
				t.stats.LostEBPFErrCount.Increment(int(lost))
				t.config.ChanErrors <- fmt.Errorf("lost %d ebpf error events", lost)
			}
		}
	}
}

package bufferdecoder

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/aquasecurity/tracee/pkg/events"
)

// FDPathFlag marks an event-local header, not a persistent task-context flag.
const FDPathFlag uint32 = 1 << 2

const fdPathHeaderSize = 8

// DecodeFDPath reads the versioned header before ordinary argument decoding.
// The header delimits both blocks, preventing corrupt arguments from consuming
// path metadata and preserving the six input slots and return-value index.
func (decoder *EbpfDecoder) DecodeFDPath() (events.FDPath, error) {
	var result events.FDPath
	remaining := decoder.buffer[decoder.cursor:]
	if len(remaining) < fdPathHeaderSize {
		return result, errors.New("FD path header is incomplete")
	}
	header := remaining[:fdPathHeaderSize]
	if header[0] != 1 || header[3] != 0 {
		return result, errors.New("unsupported FD path header version or flags")
	}
	result.ArgIndex = header[1]
	result.Status = events.FDPathStatus(header[2])
	pathSize := int(binary.LittleEndian.Uint16(header[4:6]))
	argsSize := int(binary.LittleEndian.Uint16(header[6:8]))
	if result.ArgIndex >= 6 || result.Status <= events.FDPathNone || result.Status > events.FDPathTruncated ||
		argsSize+pathSize+fdPathHeaderSize > len(remaining) || pathSize > 4096 {
		return events.FDPath{}, errors.New("invalid FD path header bounds or status")
	}
	if result.Status == events.FDPathResolved {
		if pathSize < 2 {
			return events.FDPath{}, errors.New("resolved FD path is empty")
		}
		path := remaining[fdPathHeaderSize+argsSize : fdPathHeaderSize+argsSize+pathSize]
		if path[len(path)-1] != 0 || bytes.IndexByte(path[:len(path)-1], 0) >= 0 {
			return events.FDPath{}, errors.New("invalid FD path termination")
		}
		result.Path = string(path[:len(path)-1]) // Own the bytes before the perf buffer is reused.
	} else if pathSize != 0 {
		return events.FDPath{}, errors.New("unresolved FD path contains data")
	}
	decoder.cursor += fdPathHeaderSize
	decoder.buffer = decoder.buffer[:decoder.cursor+argsSize]
	return result, nil
}

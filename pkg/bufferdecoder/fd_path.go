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
//
// The header has a fixed size, so it is skipped even when its content is
// rejected: the caller can still decode the arguments and keep the numeric FD.
func (decoder *EbpfDecoder) DecodeFDPath() (events.FDPath, error) {
	remaining := decoder.buffer[decoder.cursor:]
	if len(remaining) < fdPathHeaderSize {
		return events.FDPath{}, errors.New("FD path header is incomplete")
	}
	decoder.cursor += fdPathHeaderSize
	result, argsSize, err := parseFDPath(remaining)
	if err != nil {
		return events.FDPath{}, err
	}
	decoder.buffer = decoder.buffer[:decoder.cursor+argsSize]
	return result, nil
}

// parseFDPath validates a record that starts at its header. It returns the
// snapshot and the size of the argument block between the header and the path.
func parseFDPath(record []byte) (events.FDPath, int, error) {
	var result events.FDPath
	header := record[:fdPathHeaderSize]
	if header[0] != 1 || header[3] != 0 {
		return result, 0, errors.New("unsupported FD path header version or flags")
	}
	result.ArgIndex = header[1]
	result.Status = events.FDPathStatus(header[2])
	pathSize := int(binary.LittleEndian.Uint16(header[4:6]))
	argsSize := int(binary.LittleEndian.Uint16(header[6:8]))
	if result.ArgIndex >= 6 || result.Status <= events.FDPathNone || result.Status > events.FDPathTruncated ||
		argsSize+pathSize+fdPathHeaderSize > len(record) || pathSize > events.MaxFDPathSize {
		return events.FDPath{}, 0, errors.New("invalid FD path header bounds or status")
	}
	if result.Status != events.FDPathResolved {
		if pathSize != 0 {
			return events.FDPath{}, 0, errors.New("unresolved FD path contains data")
		}
		return result, argsSize, nil
	}
	if pathSize < 2 {
		return events.FDPath{}, 0, errors.New("resolved FD path is empty")
	}
	path := record[fdPathHeaderSize+argsSize : fdPathHeaderSize+argsSize+pathSize]
	if path[len(path)-1] != 0 || bytes.IndexByte(path[:len(path)-1], 0) >= 0 {
		return events.FDPath{}, 0, errors.New("invalid FD path termination")
	}
	result.Path = string(path[:len(path)-1]) // Own the bytes before the perf buffer is reused.
	return result, argsSize, nil
}

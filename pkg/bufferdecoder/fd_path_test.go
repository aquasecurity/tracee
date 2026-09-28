package bufferdecoder

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/data"
	"github.com/aquasecurity/tracee/types/trace"
)

func fdPathRecord(args, path []byte, index uint8, status events.FDPathStatus) []byte {
	record := append(append([]byte{}, args...), path...)
	header := []byte{1, index, byte(status), 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint16(header[4:6], uint16(len(path)))
	binary.LittleEndian.PutUint16(header[6:8], uint16(len(args)))
	return append(header, record...)
}

func TestDecodeFDPathSixArgumentsAndReturn(t *testing.T) {
	var wire bytes.Buffer
	fields := make([]events.DataField, 7)
	for i := 0; i < 6; i++ {
		fields[i] = events.DataField{ArgMeta: trace.ArgMeta{Name: fmt.Sprintf("arg%d", i), Type: "int32"}, DecodeAs: data.INT_T}
		require.NoError(t, wire.WriteByte(byte(i)))
		require.NoError(t, binary.Write(&wire, binary.LittleEndian, int32(i+10)))
	}
	fields[6] = events.DataField{ArgMeta: trace.ArgMeta{Name: "returnValue", Type: "int64"}, DecodeAs: data.LONG_T}
	require.NoError(t, wire.WriteByte(6))
	require.NoError(t, binary.Write(&wire, binary.LittleEndian, int64(-1)))
	record := fdPathRecord(wire.Bytes(), []byte("/tmp/file\x00"), 4, events.FDPathResolved)
	record = append(record, 0, 0, 0)
	decoder := New(record, NewTypeDecoder())
	path, err := decoder.DecodeFDPath()
	require.NoError(t, err)
	require.Equal(t, events.FDPath{ArgIndex: 4, Status: events.FDPathResolved, Path: "/tmp/file"}, path)
	args := make([]trace.Argument, 7)
	require.NoError(t, decoder.DecodeArguments(args, 7, fields, "mmap", events.Mmap))
	require.Equal(t, int32(14), args[4].Value)
	require.Equal(t, int64(-1), args[6].Value)
	require.Equal(t, wire.Len()+fdPathHeaderSize, decoder.BytesRead())
	// Reusing the perf record cannot alter a queued event's snapshot.
	for i := range record {
		record[i] = 0
	}
	require.Equal(t, "/tmp/file", path.Path)
}

func TestDecodeFDPathRejectsMalformedRecord(t *testing.T) {
	valid := fdPathRecord([]byte{0, 3, 0, 0, 0}, []byte("/a\x00"), 0, events.FDPathResolved)
	for _, tc := range []struct {
		name string
		edit func([]byte) []byte
	}{
		{"short", func(b []byte) []byte { return b[:7] }},
		{"version", func(b []byte) []byte { b[0] = 2; return b }},
		{"argument", func(b []byte) []byte { b[1] = 6; return b }},
		{"status", func(b []byte) []byte { b[2] = 255; return b }},
		{"flags", func(b []byte) []byte { b[3] = 1; return b }},
		{"path bounds", func(b []byte) []byte { b[4] = 65; return b }},
		{"argument bounds", func(b []byte) []byte { b[6]++; return b }},
		{"unterminated", func(b []byte) []byte { b[len(b)-1] = 'x'; return b }},
		{"embedded NUL", func(b []byte) []byte { b[len(b)-2] = 0; return b }},
		{"data on error", func(b []byte) []byte { b[2] = byte(events.FDPathReadError); return b }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decoder := New(tc.edit(append([]byte{}, valid...)), NewTypeDecoder())
			_, err := decoder.DecodeFDPath()
			require.Error(t, err)
		})
	}
}

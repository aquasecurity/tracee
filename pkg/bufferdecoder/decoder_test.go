package bufferdecoder

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestDecodeContext(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	eCtxExpected := EventContext{
		Ts:              11,
		StartTime:       0,
		CgroupID:        22,
		Pid:             543,
		Tid:             77,
		Ppid:            4567,
		HostPid:         5430,
		HostTid:         124,
		HostPpid:        555,
		Uid:             9876,
		MntID:           1357,
		PidID:           3758,
		Comm:            [16]byte{1, 3, 5, 3, 1, 5, 56, 6, 7, 32, 2, 4},
		UtsName:         [16]byte{5, 6, 7, 8, 9, 4, 3, 2},
		Flags:           0,
		LeaderStartTime: 1331,
		ParentStartTime: 1221,
		EventID:         5,
		Syscall:         0,
		Retval:          0,
		StackID:         0,
		ProcessorId:     5,
		PoliciesVersion: 11,
		MatchedPolicies: 1917,
	}
	err := binary.Write(buf, binary.LittleEndian, eCtxExpected)
	assert.Equal(t, nil, err)
	var eCtxObtained EventContext
	rawData := buf.Bytes()
	d := New(rawData)
	cursorBefore := d.cursor
	err = d.DecodeContext(&eCtxObtained)
	cursorAfter := d.cursor

	// checking no error
	assert.Equal(t, nil, err)
	// checking decoding succeeded correctly
	assert.Equal(t, eCtxExpected, eCtxObtained)
	// checking decoder cursor on buffer moved appropriately
	assert.Equal(t, int(eCtxExpected.GetSizeBytes()), cursorAfter-cursorBefore)
}

func TestDecodeUint8(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	var expected uint8 = 42
	err := binary.Write(buf, binary.LittleEndian, expected)
	// checking no error
	assert.Equal(t, nil, err)
	b := buf.Bytes()
	d := New(b)
	cursorBefore := d.cursor
	var obtained uint8
	err = d.DecodeUint8(&obtained)
	cursorAfter := d.cursor
	// checking no error
	assert.Equal(t, nil, err)
	// checking decoding succeeded correctly
	assert.Equal(t, expected, obtained)
	// checking decoder cursor on buffer moved appropriately
	assert.Equal(t, 1, cursorAfter-cursorBefore) // cursor should move 1 byte
}

func TestDecodeInt8(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	var expected int8 = -42
	err := binary.Write(buf, binary.LittleEndian, expected)
	// checking no error
	assert.Equal(t, nil, err)
	b := buf.Bytes()
	d := New(b)
	cursorBefore := d.cursor
	var obtained int8
	err = d.DecodeInt8(&obtained)
	cursorAfter := d.cursor
	// checking no error
	assert.Equal(t, nil, err)
	// checking decoding succeeded correctly
	assert.Equal(t, expected, obtained)
	// checking decoder cursor on buffer moved appropriately
	assert.Equal(t, 1, cursorAfter-cursorBefore) // cursor should move 1 byte
}

func TestDecodeUint16(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	var expected uint16 = 5555
	err := binary.Write(buf, binary.LittleEndian, expected)
	// checking no error
	assert.Equal(t, nil, err)
	b := buf.Bytes()
	d := New(b)
	cursorBefore := d.cursor
	var obtained uint16
	err = d.DecodeUint16(&obtained)
	cursorAfter := d.cursor
	// checking no error
	assert.Equal(t, nil, err)
	// checking decoding succeeded correctly
	assert.Equal(t, expected, obtained)
	// checking decoder cursor on buffer moved appropriately
	assert.Equal(t, 2, cursorAfter-cursorBefore) // cursor should move 2 byte
}

func TestDecodeUint16BigEndian(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	var expected uint16 = 5555
	err := binary.Write(buf, binary.BigEndian, expected)
	// checking no error
	assert.Equal(t, nil, err)
	b := buf.Bytes()
	d := New(b)
	cursorBefore := d.cursor
	var obtained uint16
	err = d.DecodeUint16BigEndian(&obtained)
	cursorAfter := d.cursor
	// checking no error
	assert.Equal(t, nil, err)
	// checking decoding succeeded correctly
	assert.Equal(t, expected, obtained)
	// checking decoder cursor on buffer moved appropriately
	assert.Equal(t, 2, cursorAfter-cursorBefore) // cursor should move 2 byte
}
func TestDecodeInt16(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	var expected int16 = -3456
	err := binary.Write(buf, binary.LittleEndian, expected)
	// checking no error
	assert.Equal(t, nil, err)
	b := buf.Bytes()
	d := New(b)
	cursorBefore := d.cursor
	var obtained int16
	err = d.DecodeInt16(&obtained)
	cursorAfter := d.cursor
	// checking no error
	assert.Equal(t, nil, err)
	// checking decoding succeeded correctly
	assert.Equal(t, expected, obtained)
	// checking decoder cursor on buffer moved appropriately
	assert.Equal(t, 2, cursorAfter-cursorBefore) // cursor should move 2 byte
}

func TestDecodeUint32(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	var expected uint32 = 5555
	err := binary.Write(buf, binary.LittleEndian, expected)
	// checking no error
	assert.Equal(t, nil, err)
	b := buf.Bytes()
	d := New(b)
	cursorBefore := d.cursor
	var obtained uint32
	err = d.DecodeUint32(&obtained)
	cursorAfter := d.cursor
	// checking no error
	assert.Equal(t, nil, err)
	// checking decoding succeeded correctly
	assert.Equal(t, expected, obtained)
	// checking decoder cursor on buffer moved appropriately
	assert.Equal(t, cursorAfter-cursorBefore, 4) // cursor should move 4 byte
}

func TestDecodeUint32BigEndian(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	var expected uint32 = 5555
	err := binary.Write(buf, binary.BigEndian, expected)
	// checking no error
	assert.Equal(t, nil, err)
	b := buf.Bytes()
	d := New(b)
	cursorBefore := d.cursor
	var obtained uint32
	err = d.DecodeUint32BigEndian(&obtained)
	cursorAfter := d.cursor
	// checking no error
	assert.Equal(t, nil, err)
	// checking decoding succeeded correctly
	assert.Equal(t, expected, obtained)
	// checking decoder cursor on buffer moved appropriately
	assert.Equal(t, cursorAfter-cursorBefore, 4) // cursor should move 4 byte
}
func TestDecodeInt32(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	var expected int32 = -3456
	err := binary.Write(buf, binary.LittleEndian, expected)
	// checking no error
	assert.Equal(t, nil, err)
	b := buf.Bytes()
	d := New(b)
	cursorBefore := d.cursor
	var obtained int32
	err = d.DecodeInt32(&obtained)
	cursorAfter := d.cursor
	// checking no error
	assert.Equal(t, nil, err)
	// checking decoding succeeded correctly
	assert.Equal(t, expected, obtained)
	// checking decoder cursor on buffer moved appropriately
	assert.Equal(t, 4, cursorAfter-cursorBefore) // cursor should move 4 byte
}

func TestDecodeUint64(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	var expected uint64 = 5555
	err := binary.Write(buf, binary.LittleEndian, expected)
	// checking no error
	assert.Equal(t, nil, err)
	b := buf.Bytes()
	d := New(b)
	cursorBefore := d.cursor
	var obtained uint64
	err = d.DecodeUint64(&obtained)
	cursorAfter := d.cursor
	// checking no error
	assert.Equal(t, nil, err)
	// checking decoding succeeded correctly
	assert.Equal(t, expected, obtained)
	// checking decoder cursor on buffer moved appropriately
	assert.Equal(t, 8, cursorAfter-cursorBefore) // cursor should move 8 byte
}

func TestDecodeInt64(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	var expected int64 = -3456
	err := binary.Write(buf, binary.LittleEndian, expected)
	// checking no error
	assert.Equal(t, nil, err)
	b := buf.Bytes()
	d := New(b)
	cursorBefore := d.cursor
	var obtained int64
	err = d.DecodeInt64(&obtained)
	cursorAfter := d.cursor
	// checking no error
	assert.Equal(t, nil, err)
	// checking decoding succeeded correctly
	assert.Equal(t, expected, obtained)
	// checking decoder cursor on buffer moved appropriately
	assert.Equal(t, 8, cursorAfter-cursorBefore) // cursor should move 8 byte
}

func TestDecodeBoolTrue(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	expected := true
	err := binary.Write(buf, binary.LittleEndian, expected)
	// checking no error
	assert.Equal(t, nil, err)
	b := buf.Bytes()
	d := New(b)
	cursorBefore := d.cursor
	var obtained bool
	err = d.DecodeBool(&obtained)
	cursorAfter := d.cursor
	// checking no error
	assert.Equal(t, nil, err)
	// checking decoding succeeded correctly
	assert.Equal(t, expected, obtained)
	// checking decoder cursor on buffer moved appropriately
	assert.Equal(t, 1, cursorAfter-cursorBefore) // cursor should move 1 byte
}

func TestDecodeBoolFalse(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	expected := false
	err := binary.Write(buf, binary.LittleEndian, expected)
	// checking no error
	assert.Equal(t, nil, err)
	b := buf.Bytes()
	d := New(b)
	cursorBefore := d.cursor
	var obtained bool
	err = d.DecodeBool(&obtained)
	cursorAfter := d.cursor
	// checking no error
	assert.Equal(t, nil, err)
	// checking decoding succeeded correctly
	assert.Equal(t, expected, obtained)
	// checking decoder cursor on buffer moved appropriately
	assert.Equal(t, 1, cursorAfter-cursorBefore) // cursor should move 1 byte
}

// TODO DecodeBytes and DecodeIntArray
func TestDecodeBytes(t *testing.T) {
	t.Parallel()

	type JustAStruct struct {
		A1 uint32
		A2 uint64
	}
	expected := JustAStruct{
		A1: 43,
		A2: 444434,
	}
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, &expected)
	assert.Equal(t, nil, err)

	var sunPathBuf [12]byte // 12 is the size of JustAStruct
	d := New(buf.Bytes())
	err = d.DecodeBytes(sunPathBuf[:], 12)
	assert.Equal(t, nil, err)

	r := bytes.NewBuffer(sunPathBuf[:])
	var obtained JustAStruct
	err = binary.Read(r, binary.LittleEndian, &obtained)
	assert.Equal(t, nil, err)
	assert.Equal(t, expected, obtained)
}

func TestDecodeIntArray(t *testing.T) {
	t.Parallel()

	var raw []byte
	raw = append(raw, 1, 2, 3, 4, 5, 6, 7, 8)
	decoder := New(raw)
	var obtained [2]int32
	err := decoder.DecodeIntArray(obtained[:], 2)
	assert.Equal(t, nil, err)
	rawcp := append(raw, 1, 2, 3, 4, 5, 6, 7, 8)
	dataBuff := bytes.NewBuffer(rawcp)
	var expected [2]int32
	err = binary.Read(dataBuff, binary.LittleEndian, &expected)
	assert.Equal(t, nil, err)
	// checking decoding works as expected
	assert.Equal(t, expected, obtained)
}

func TestDecodeSlimCred(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	expected := SlimCred{
		Uid:            43,
		Gid:            6789,
		Suid:           987,
		Sgid:           678,
		Euid:           543,
		Egid:           7538,
		Fsuid:          687,
		Fsgid:          3454,
		UserNamespace:  34,
		SecureBits:     456789,
		CapInheritable: 342,
		CapPermitted:   9873,
		CapEffective:   555,
		CapBounding:    5555,
		CapAmbient:     432,
	}
	err := binary.Write(buf, binary.LittleEndian, expected)
	assert.Equal(t, nil, err)
	var obtained SlimCred
	rawBuf := buf.Bytes()
	d := New(rawBuf)
	err = d.DecodeSlimCred(&obtained)
	assert.Equal(t, nil, err)
	assert.Equal(t, expected, obtained)
}

func TestDecodeChunkMeta(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	expected := ChunkMeta{
		BinType:  54,
		CgroupID: 6543,
		Metadata: [28]byte{5, 4, 3, 5, 6, 7, 4, 54, 3, 32, 4, 4, 4, 4, 4},
		Size:     6543,
		Off:      76543,
	}
	err := binary.Write(buf, binary.LittleEndian, expected)
	assert.Equal(t, nil, err)
	var obtained ChunkMeta
	rawBuf := buf.Bytes()
	d := New(rawBuf)
	err = d.DecodeChunkMeta(&obtained)
	assert.Equal(t, nil, err)
	assert.Equal(t, expected, obtained)
}

func TestDecodeVfsWriteMeta(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	expected := VfsFileMeta{
		DevID: 54,
		Inode: 543,
		Mode:  654,
		Pid:   98479,
	}
	err := binary.Write(buf, binary.LittleEndian, expected)
	assert.Equal(t, nil, err)
	var obtained VfsFileMeta
	rawBuf := buf.Bytes()
	d := New(rawBuf)
	err = d.DecodeVfsFileMeta(&obtained)
	assert.Equal(t, nil, err)
	assert.Equal(t, expected, obtained)
}

func TestDecodeKernelModuleMeta(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	expected := KernelModuleMeta{
		DevID: 7489,
		Inode: 543,
		Pid:   7654,
		Size:  4533,
	}
	err := binary.Write(buf, binary.LittleEndian, expected)
	assert.Equal(t, nil, err)
	var obtained KernelModuleMeta
	rawBuf := buf.Bytes()
	d := New(rawBuf)
	err = d.DecodeKernelModuleMeta(&obtained)
	assert.Equal(t, nil, err)
	assert.Equal(t, expected, obtained)
}

func TestDecodeBpfObjectMeta(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	expected := BpfObjectMeta{
		Name: [16]byte{80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80},
		Rand: 543,
		Pid:  7654,
		Size: 4533,
	}
	err := binary.Write(buf, binary.LittleEndian, expected)
	assert.Equal(t, nil, err)
	var obtained BpfObjectMeta
	rawBuf := buf.Bytes()
	d := New(rawBuf)
	err = d.DecodeBpfObjectMeta(&obtained)
	assert.Equal(t, nil, err)
	assert.Equal(t, expected, obtained)
}

func TestDecodeMprotectWriteMeta(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	expected := MprotectWriteMeta{
		Pid: 12,
		Ts:  6789,
	}
	err := binary.Write(buf, binary.LittleEndian, expected)
	assert.Equal(t, nil, err)
	var obtained MprotectWriteMeta
	rawBuf := buf.Bytes()
	d := New(rawBuf)
	err = d.DecodeMprotectWriteMeta(&obtained)
	assert.Equal(t, nil, err)
	assert.Equal(t, expected, obtained)
}

func BenchmarkDecodeContext(*testing.B) {
	var eCtx EventContext
	/*
		eCtx := EventContext{
			Ts:          11,
			ProcessorId: 32,
			CgroupID:    22,
			Pid:         543,
			Tid:         77,
			Ppid:        4567,
			HostPid:     5430,
			HostTid:     124,
			HostPpid:    555,
			Uid:         9876,
			MntID:       1357,
			PidID:       3758,
			Comm:        [16]byte{1, 3, 5, 3, 1, 5, 56, 6, 7, 32, 2, 4},
			UtsName:     [16]byte{5, 6, 7, 8, 9, 4, 3, 2},
			EventID:     654,
			Retval:      6543,
			StackID:     6,
			Argnum:      234,
		}
		******************
		buffer is the []byte representation of s instance
		******************
	*/
	buffer := []byte{11, 0, 0, 0, 0, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 176, 1, 0, 0, 0, 0, 0, 0, 31, 2, 0, 0, 77, 0, 0, 0, 215, 17, 0, 0,
		54, 21, 0, 0, 124, 0, 0, 0, 43, 2, 0, 0, 148, 38, 0, 0, 77, 5, 0, 0, 174, 14, 0, 0, 1, 3, 5, 3, 1, 5, 56, 6, 7, 32,
		2, 4, 0, 0, 0, 0, 5, 6, 7, 8, 9, 4, 3, 2, 0, 0, 0, 0, 0, 0, 0, 0, 142, 2, 0, 0, 143, 25, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 234,
		0, 0, 0}
	for i := 0; i < 100; i++ {
		decoder := New(buffer)
		decoder.DecodeContext(&eCtx)
	}
}
func BenchmarkBinaryContext(*testing.B) {
	var eCtx EventContext
	/*
		eCtx := EventContext{
			Ts:       11,
			CgroupID: 22,
			ProcessorId: 432,
			Pid:      543,
			Tid:      77,
			Ppid:     4567,
			HostPid:  5430,
			HostTid:  124,
			HostPpid: 555,
			Uid:      9876,
			MntID:    1357,
			PidID:    3758,
			Comm:     [16]byte{1, 3, 5, 3, 1, 5, 56, 6, 7, 32, 2, 4},
			UtsName:  [16]byte{5, 6, 7, 8, 9, 4, 3, 2},
			EventID:  654,
			Retval:   6543,
			StackID:  6,
			Argnum:   234,
		}
		******************
		buffer is the []byte representation of s instance
		******************
	*/

	buffer := []byte{11, 0, 0, 0, 0, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 176, 1, 0, 0, 0, 0, 0, 0, 31, 2, 0, 0, 77, 0, 0, 0, 215, 17, 0, 0,
		54, 21, 0, 0, 124, 0, 0, 0, 43, 2, 0, 0, 148, 38, 0, 0, 77, 5, 0, 0, 174, 14, 0, 0, 1, 3, 5, 3, 1, 5, 56, 6, 7, 32,
		2, 4, 0, 0, 0, 0, 5, 6, 7, 8, 9, 4, 3, 2, 0, 0, 0, 0, 0, 0, 0, 0, 142, 2, 0, 0, 143, 25, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 234,
		0, 0, 0}
	for i := 0; i < 100; i++ {
		binBuf := bytes.NewBuffer(buffer)
		binary.Read(binBuf, binary.LittleEndian, &eCtx)
	}
}

func BenchmarkDecodeUint8(*testing.B) {
	buffer := []byte{234}
	var num uint8
	for i := 0; i < 100; i++ {
		decoder := New(buffer)
		decoder.DecodeUint8(&num)
	}
}

func BenchmarkBinaryUint8(*testing.B) {
	buffer := []byte{234}
	var num uint8
	for i := 0; i < 100; i++ {
		decoder := bytes.NewBuffer(buffer)
		binary.Read(decoder, binary.LittleEndian, &num)
	}
}

func BenchmarkDecodeInt8(*testing.B) {
	buffer := []byte{234}
	var num int8
	for i := 0; i < 100; i++ {
		decoder := New(buffer)
		decoder.DecodeInt8(&num)
	}
}

func BenchmarkBinaryInt8(*testing.B) {
	buffer := []byte{234}
	var num int8
	for i := 0; i < 100; i++ {
		decoder := bytes.NewBuffer(buffer)
		binary.Read(decoder, binary.LittleEndian, &num)
	}
}

func BenchmarkDecodeUint16(*testing.B) {
	buffer := []byte{179, 21}
	var num uint16
	for i := 0; i < 100; i++ {
		decoder := New(buffer)
		decoder.DecodeUint16(&num)
	}
}

func BenchmarkBinaryUint16(*testing.B) {
	buffer := []byte{179, 21}
	var num uint16
	for i := 0; i < 100; i++ {
		decoder := bytes.NewBuffer(buffer)
		binary.Read(decoder, binary.LittleEndian, &num)
	}
}

func BenchmarkDecodeInt16(*testing.B) {
	buffer := []byte{179, 221}
	var num int16
	for i := 0; i < 100; i++ {
		decoder := New(buffer)
		decoder.DecodeInt16(&num)
	}
}

func BenchmarkBinaryInt16(*testing.B) {
	buffer := []byte{179, 221}
	var num int16
	for i := 0; i < 100; i++ {
		decoder := bytes.NewBuffer(buffer)
		binary.Read(decoder, binary.LittleEndian, &num)
	}
}

func BenchmarkDecodeUint32(*testing.B) {
	buffer := []byte{179, 21, 56, 234}
	var num uint32
	for i := 0; i < 100; i++ {
		decoder := New(buffer)
		decoder.DecodeUint32(&num)
	}
}

func BenchmarkBinaryUint32(*testing.B) {
	buffer := []byte{179, 21, 56, 234}
	var num uint32
	for i := 0; i < 100; i++ {
		decoder := bytes.NewBuffer(buffer)
		binary.Read(decoder, binary.LittleEndian, &num)
	}
}
func BenchmarkDecodeInt32(*testing.B) {
	buffer := []byte{179, 21, 56, 234}
	var num int32
	for i := 0; i < 100; i++ {
		decoder := New(buffer)
		decoder.DecodeInt32(&num)
	}
}

func BenchmarkBinaryInt32(*testing.B) {
	buffer := []byte{179, 21, 56, 234}
	var num int32
	for i := 0; i < 100; i++ {
		decoder := bytes.NewBuffer(buffer)
		binary.Read(decoder, binary.LittleEndian, &num)
	}
}

func BenchmarkDecodeUint64(*testing.B) {
	buffer := []byte{179, 21, 56, 234, 45, 65, 234, 255}
	var num uint64
	for i := 0; i < 100; i++ {
		decoder := New(buffer)
		decoder.DecodeUint64(&num)
	}
}

func BenchmarkBinaryUint64(*testing.B) {
	buffer := []byte{179, 21, 56, 234, 45, 65, 234, 255}
	var num uint64
	for i := 0; i < 100; i++ {
		decoder := bytes.NewBuffer(buffer)
		binary.Read(decoder, binary.LittleEndian, &num)
	}
}

func BenchmarkDecodeInt64(*testing.B) {
	buffer := []byte{179, 21, 56, 234, 45, 65, 234, 255}
	var num int64
	for i := 0; i < 100; i++ {
		decoder := New(buffer)
		decoder.DecodeInt64(&num)
	}
}

func BenchmarkBinaryInt64(*testing.B) {
	buffer := []byte{179, 21, 56, 234, 45, 65, 234, 255}
	var num int64
	for i := 0; i < 100; i++ {
		decoder := bytes.NewBuffer(buffer)
		binary.Read(decoder, binary.LittleEndian, &num)
	}
}

func BenchmarkDecodeBool(*testing.B) {
	buffer := []byte{1}
	var num bool
	for i := 0; i < 100; i++ {
		decoder := New(buffer)
		decoder.DecodeBool(&num)
	}
}
func BenchmarkBinaryBool(*testing.B) {
	buffer := []byte{1}
	var num bool
	for i := 0; i < 100; i++ {
		decoder := bytes.NewBuffer(buffer)
		binary.Read(decoder, binary.LittleEndian, &num)
	}
}

func BenchmarkDecodeSlimCred(*testing.B) {
	/*
		s := bufferdecoder.SlimCred{
			Uid:            12,
			Gid:            34,
			Suid:           56,
			Sgid:           78,
			Euid:           91,
			Egid:           234,
			Fsuid:          654,
			Fsgid:          765,
			UserNamespace:  7654,
			SecureBits:     7654,
			CapInheritable: 345,
			CapPermitted:   234,
			CapEffective:   7653,
			CapBounding:    8765,
			CapAmbient:     765423,
		}

		******************
		buffer is the []byte representation of s instance
		******************
	*/
	buffer := []byte{12, 0, 0, 0, 34, 0, 0, 0, 56, 0, 0, 0, 78, 0, 0, 0, 91, 0, 0, 0, 234, 0, 0, 0, 142, 2, 0, 0, 253, 2, 0, 0,
		230, 29, 0, 0, 230, 29, 0, 0, 89, 1, 0, 0, 0, 0, 0, 0, 234, 0, 0, 0, 0, 0, 0, 0, 229, 29, 0, 0, 0, 0, 0, 0,
		61, 34, 0, 0, 0, 0, 0, 0, 239, 173, 11, 0, 0, 0, 0, 0}
	var s SlimCred
	for i := 0; i < 100; i++ {
		decoder := New(buffer)
		decoder.DecodeSlimCred(&s)
	}
}

func BenchmarkBinarySlimCred(*testing.B) {
	/*
		s := bufferdecoder.SlimCred{
			Uid:            12,
			Gid:            34,
			Suid:           56,
			Sgid:           78,
			Euid:           91,
			Egid:           234,
			Fsuid:          654,
			Fsgid:          765,
			UserNamespace:  7654,
			SecureBits:     7654,
			CapInheritable: 345,
			CapPermitted:   234,
			CapEffective:   7653,
			CapBounding:    8765,
			CapAmbient:     765423,
		}

		******************
		buffer is the []byte representation of s instance
		******************
	*/
	buffer := []byte{12, 0, 0, 0, 34, 0, 0, 0, 56, 0, 0, 0, 78, 0, 0, 0, 91, 0, 0, 0, 234, 0, 0, 0, 142, 2, 0, 0, 253, 2, 0, 0,
		230, 29, 0, 0, 230, 29, 0, 0, 89, 1, 0, 0, 0, 0, 0, 0, 234, 0, 0, 0, 0, 0, 0, 0, 229, 29, 0, 0, 0, 0, 0, 0,
		61, 34, 0, 0, 0, 0, 0, 0, 239, 173, 11, 0, 0, 0, 0, 0}
	var s trace.SlimCred
	for i := 0; i < 100; i++ {
		binBuf := bytes.NewBuffer(buffer)
		binary.Read(binBuf, binary.LittleEndian, &s)
	}
}

func BenchmarkDecodeChunkMeta(*testing.B) {
	/*
		s := ChunkMeta{
			BinType:  1,
			CgroupID: 54,
			Metadata: [24]byte{
				54,
				12,
				54,
				145,
				42,
				72,
				134,
				64,
				125,
				53,
				62,
				62,
				123,
				255,
				123,
				5,
				0,
				32,
				234,
				23,
				42,
				123,
				32,
				2,
			},
			Size: 2,
			Off:  23,
		}
		******************
		buffer is the []byte representation of s instance
		******************
	*/
	buffer := []byte{1, 54, 0, 0, 0, 0, 0, 0, 0, 54, 12, 54, 145, 42, 72, 134, 64, 125, 53, 62, 62, 123, 255, 123, 5, 0, 32, 234,
		23, 42, 123, 32, 2, 2, 0, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0}
	var s ChunkMeta
	for i := 0; i < 100; i++ {
		decoder := New(buffer)
		decoder.DecodeChunkMeta(&s)
	}
}
func BenchmarkBinaryChunkMeta(*testing.B) {
	/*
		s := ChunkMeta{
			BinType:  1,
			CgroupID: 54,
			Metadata: [24]byte{
				54,
				12,
				54,
				145,
				42,
				72,
				134,
				64,
				125,
				53,
				62,
				62,
				123,
				255,
				123,
				5,
				0,
				32,
				234,
				23,
				42,
				123,
				32,
				2,
			},
			Size: 2,
			Off:  23,
		}
		******************
		buffer is the []byte representation of s instance
		******************
	*/
	buffer := []byte{1, 54, 0, 0, 0, 0, 0, 0, 0, 54, 12, 54, 145, 42, 72, 134, 64, 125, 53, 62, 62, 123, 255, 123, 5, 0, 32, 234,
		23, 42, 123, 32, 2, 2, 0, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0}
	var s ChunkMeta
	for i := 0; i < 100; i++ {
		binBuf := bytes.NewBuffer(buffer)
		binary.Read(binBuf, binary.LittleEndian, &s)
	}
}

func BenchmarkDecodeVfsWriteMeta(*testing.B) {
	/*
		s := VfsFileMeta{
			DevID: 24,
			Inode: 3,
			Mode:  255,
			Pid:   0,
		}
		******************
		buffer is the []byte representation of s instance
		******************
	*/

	buffer := []byte{24, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0}
	var s VfsFileMeta
	for i := 0; i < 100; i++ {
		decoder := New(buffer)
		decoder.DecodeVfsFileMeta(&s)
	}
}

func BenchmarkBinaryVfsWriteMeta(*testing.B) {
	/*
		s := VfsFileMeta{
			DevID: 24,
			Inode: 3,
			Mode:  255,
			Pid:   0,
		}
		******************
		buffer is the []byte representation of s instance
		******************
	*/

	buffer := []byte{24, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0}
	var s VfsFileMeta
	for i := 0; i < 100; i++ {
		binBuf := bytes.NewBuffer(buffer)
		binary.Read(binBuf, binary.LittleEndian, &s)
	}
}

func BenchmarkDecodeKernelModuleMeta(*testing.B) {
	/*
		s := KernelModuleMeta{
			DevID: 43,
			Inode: 65,
			Pid:   234,
			Size:  1,
		}
		******************
		buffer is the []byte representation of s instance
		******************
	*/
	buffer := []byte{43, 0, 0, 0, 65, 0, 0, 0, 0, 0, 0, 0, 234, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0}
	var s KernelModuleMeta
	for i := 0; i < 100; i++ {
		decoder := New(buffer)
		decoder.DecodeKernelModuleMeta(&s)
	}
}

func BenchmarkBinaryKernelModuleMeta(*testing.B) {
	/*
		s := KernelModuleMeta{
			DevID: 43,
			Inode: 65,
			Pid:   234,
			Size:  1,
		}
		******************
		buffer is the []byte representation of s instance
		******************
	*/
	buffer := []byte{43, 0, 0, 0, 65, 0, 0, 0, 0, 0, 0, 0, 234, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0}
	var s KernelModuleMeta
	for i := 0; i < 100; i++ {
		binBuf := bytes.NewBuffer(buffer)
		binary.Read(binBuf, binary.LittleEndian, &s)
	}
}

func BenchmarkDecodeMprotectWriteMeta(*testing.B) {
	/*
		s := MprotectWriteMeta{
			Ts: 123,
		}
		******************
		buffer is the []byte representation of s instance
		******************
	*/
	buffer := []byte{123, 0, 0, 0, 0, 0, 0, 0}
	var s MprotectWriteMeta
	for i := 0; i < 100; i++ {
		decoder := New(buffer)
		decoder.DecodeMprotectWriteMeta(&s)
	}
}

func BenchmarkBinaryMprotectWriteMeta(*testing.B) {
	/*
		s := MprotectWriteMeta{
			Ts: 123,
		}
		******************
		buffer is the []byte representation of s instance
		******************
	*/
	buffer := []byte{123, 0, 0, 0, 0, 0, 0, 0}
	var s MprotectWriteMeta
	for i := 0; i < 100; i++ {
		binBuf := bytes.NewBuffer(buffer)
		binary.Read(binBuf, binary.LittleEndian, &s)
	}
}

func BenchmarkDecodeArguments(b *testing.B) {
	/*
		args := []trace.Argument{
			{
				Name: "arg1",
				Type: "u64",
				Value: 1,
			},
			{
				Name: "arg2",
				Type: "u64",
				Value: 2,
			},
			{
				Name: "arg3",
				Type: "u64",
				Value: 3,
			},
			...
		}
		******************
		buffer is the []byte representation of args instance
		******************
	*/

	buffer := []byte{
		0, 1, 0, 0, 0, 0, 0, 0, 0, // arg1
		1, 2, 0, 0, 0, 0, 0, 0, 0, // arg2
		2, 3, 0, 0, 0, 0, 0, 0, 0, // arg3
		3, 4, 0, 0, 0, 0, 0, 0, 0, // arg4
		4, 5, 0, 0, 0, 0, 0, 0, 0, // arg5
		5, 6, 0, 0, 0, 0, 0, 0, 0, // arg6
		6, 7, 0, 0, 0, 0, 0, 0, 0, // arg7
		7, 8, 0, 0, 0, 0, 0, 0, 0, // arg8
	}
	evtFields := []trace.ArgMeta{
		{Name: "arg1", Type: "u64", Zero: 0},
		{Name: "arg2", Type: "u64", Zero: 0},
		{Name: "arg3", Type: "u64", Zero: 0},
		{Name: "arg4", Type: "u64", Zero: 0},
		{Name: "arg5", Type: "u64", Zero: 0},
		{Name: "arg6", Type: "u64", Zero: 0},
		{Name: "arg7", Type: "u64", Zero: 0},
		{Name: "arg8", Type: "u64", Zero: 0},
	}

	// decode half of the arguments leaving the rest to be populated as zero values
	argnum := len(evtFields) / 2

	evtVersion := events.NewVersion(1, 0, 0)
	evtName := "test"
	eventId := events.ID(0)
	evtDef := events.NewDefinition(
		eventId,
		eventId+1000,
		evtName,
		evtVersion,
		"",
		"",
		false,
		false,
		[]string{},
		events.Dependencies{},
		evtFields, // fields
		nil,
	)

	events.Core.AddBatch(map[events.ID]events.Definition{eventId: evtDef})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decoder := New(buffer)
		args := make([]trace.Argument, len(evtFields))
		_ = decoder.DecodeArguments(args, argnum, evtFields, evtName, eventId)
	}
}

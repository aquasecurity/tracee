package bufferdecoder

import (
	"bytes"
	"testing"
)

func BenchmarkReadStringVarFromBuff_ShortString(b *testing.B) {
	buffer := []byte{'H', 'e', 'l', 'l', 'o', 0}
	max := 10
	var str string

	for i := 0; i < b.N; i++ {
		decoder := New(buffer)
		str, _ = readStringVarFromBuff(decoder, max)
	}
	_ = str
}

func BenchmarkReadStringVarFromBuff_MediumString(b *testing.B) {
	buffer := []byte{'T', 'h', 'i', 's', ' ', 'i', 's', ' ', 'a', ' ', 't', 'e', 's', 't', 0}
	max := 20
	var str string

	for i := 0; i < b.N; i++ {
		decoder := New(buffer)
		str, _ = readStringVarFromBuff(decoder, max)
	}
	_ = str
}

func BenchmarkReadStringVarFromBuff_LongString(b *testing.B) {
	buffer := append(bytes.Repeat([]byte{'A'}, 10000), 0)
	max := 10000
	var str string

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decoder := New(buffer)
		str, _ = readStringVarFromBuff(decoder, max)
	}
	_ = str
}

func BenchmarkReadStringVarFromBuff_LongStringLowMax(b *testing.B) {
	buffer := bytes.Repeat([]byte{'A'}, 10000)
	max := 100
	var str string

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decoder := New(buffer)
		str, _ = readStringVarFromBuff(decoder, max)
	}
	_ = str
}

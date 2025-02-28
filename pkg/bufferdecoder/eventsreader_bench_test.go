package bufferdecoder

import (
	"bytes"
	"testing"
)

var present = NewTypeDecoder()

func Benchmark_readSunPathFromBuff_ShortString(b *testing.B) {
	buffer := []byte{'H', 'e', 'l', 'l', 'o', 0}
	max := 10
	var str string

	for b.Loop() {
		decoder := New(buffer, present)
		str, _ = readSunPathFromBuff(decoder, max)
	}
	_ = str
}

func Benchmark_readSunPathFromBuff_MediumString(b *testing.B) {
	buffer := []byte{'T', 'h', 'i', 's', ' ', 'i', 's', ' ', 'a', ' ', 't', 'e', 's', 't', 0}
	max := 20
	var str string

	for b.Loop() {
		decoder := New(buffer, present)
		str, _ = readSunPathFromBuff(decoder, max)
	}
	_ = str
}

func Benchmark_readSunPathFromBuff_AbstractSocket(b *testing.B) {
	buffer := []byte{0, 'A', 'b', 's', 't', 'r', 'a', 'c', 't', 0}
	max := 10
	var str string

	for b.Loop() {
		decoder := New(buffer, present)
		str, _ = readSunPathFromBuff(decoder, max)
	}
	_ = str
}

func Benchmark_readSunPathFromBuff_LongString(b *testing.B) {
	buffer := append(bytes.Repeat([]byte{'A'}, 10000), 0)
	max := 10000
	var str string

	for b.Loop() {
		decoder := New(buffer, present)
		str, _ = readSunPathFromBuff(decoder, max)
	}
	_ = str
}

func Benchmark_readSunPathFromBuff_LongStringLowMax(b *testing.B) {
	buffer := bytes.Repeat([]byte{'A'}, 10000)
	max := 100
	var str string

	for b.Loop() {
		decoder := New(buffer, present)
		str, _ = readSunPathFromBuff(decoder, max)
	}
	_ = str
}

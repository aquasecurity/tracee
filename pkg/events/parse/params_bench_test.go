package parse

import (
	"testing"

	"github.com/aquasecurity/tracee/types/trace"
)

var args = []trace.Argument{
	{
		ArgMeta: trace.ArgMeta{
			Name: "valid_arg1",
			Type: "int",
		},
		Value: int32(1878),
	},
	{
		ArgMeta: trace.ArgMeta{
			Name: "valid_arg2",
			Type: "int",
		},
		Value: int32(1878),
	},
	{
		ArgMeta: trace.ArgMeta{
			Name: "invalid_val_type", // in the middle of the list
			Type: "int",
		},
		Value: int64(1878),
	},
	{
		ArgMeta: trace.ArgMeta{
			Name: "valid_arg3",
			Type: "int",
		},
		Value: int32(1878),
	},
}

func BenchmarkArgVal(b *testing.B) {
	b.Run("int32", func(b *testing.B) {
		b.Run("valid_args", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _ = ArgVal[int32](args, "valid_arg1")
				_, _ = ArgVal[int32](args, "valid_arg2")
				_, _ = ArgVal[int32](args, "valid_arg3")
			}
		})
		b.Run("invalid_val_type", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _ = ArgVal[int32](args, "invalid_val_type")
			}
		})
		b.Run("not_found_arg", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _ = ArgVal[int32](args, "not_found_arg")
			}
		})
	})
}

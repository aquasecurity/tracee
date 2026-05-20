package symbol

import (
	"fmt"
	"strings"
	"testing"
)

// buildKallsymsBuffer produces a synthetic /proc/kallsyms-like buffer with the
// given number of symbol lines, simulating a realistic mix of name lengths and
// owners. A handful of owner strings are reused across many symbols (matching
// how real kallsyms looks: most modules contribute multiple symbols).
func buildKallsymsBuffer(numSymbols int) string {
	owners := []string{
		"system",
		"libbpf",
		"bpf",
		"nf_tables",
		"i915",
		"snd_hda_intel",
		"kvm_intel",
		"ext4",
		"overlay",
	}

	var b strings.Builder
	b.Grow(numSymbols * 64)
	for i := 0; i < numSymbols; i++ {
		addr := uint64(0xffffffff00000000) | uint64(i+1)
		// Sprinkle some name reuse to exercise intern dedup
		var name string
		switch i % 5 {
		case 0:
			name = fmt.Sprintf("sys_call_%06d", i)
		case 1:
			name = fmt.Sprintf("__do_softirq_%06d", i)
		case 2:
			name = "kfree" // repeats: identical name across many addresses
		case 3:
			name = fmt.Sprintf("vfs_read_%06d", i)
		default:
			name = "schedule" // repeats
		}

		if i%7 == 0 {
			// System symbol (no owner column)
			fmt.Fprintf(&b, "%016x t %s\n", addr, name)
		} else {
			owner := owners[i%len(owners)]
			fmt.Fprintf(&b, "%016x t %s [%s]\n", addr, name, owner)
		}
	}
	return b.String()
}

func BenchmarkKernelSymbolTableUpdate(b *testing.B) {
	buf := buildKallsymsBuffer(200_000)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := NewKernelSymbolTableFromReader(strings.NewReader(buf), false, false)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkKernelSymbolTableUpdateLazy exercises the lazy-name-lookup path
// used by most production callers (cheaper map maintenance during load).
func BenchmarkKernelSymbolTableUpdateLazy(b *testing.B) {
	buf := buildKallsymsBuffer(200_000)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := NewKernelSymbolTableFromReader(strings.NewReader(buf), true, false)
		if err != nil {
			b.Fatal(err)
		}
	}
}

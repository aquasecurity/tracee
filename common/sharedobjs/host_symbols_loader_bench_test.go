package sharedobjs

import (
	"debug/elf"
	"fmt"
	"testing"
)

// benchSymbolSetDeduped builds inputs where every name repeats. This stresses
// the intern (unique) deduplication path because intern.String can fold every
// occurrence onto one canonical handle.
func benchSymbolSetDeduped(n int) (static, dyn []elf.Symbol) {
	static = make([]elf.Symbol, 0, n/2)
	dyn = make([]elf.Symbol, 0, n/2)
	for i := 0; i < n/2; i++ {
		static = append(static, elf.Symbol{Name: "local_sym", Value: uint64(i + 1)})
	}
	for i := 0; i < n/2; i++ {
		if i%3 == 0 {
			dyn = append(dyn, elf.Symbol{Name: "import_sym", Library: "libc.so.6", Value: 0})
		} else {
			dyn = append(dyn, elf.Symbol{Name: "export_sym", Value: uint64(i + 1)})
		}
	}
	return static, dyn
}

// benchSymbolSetUnique builds inputs where every name is distinct. This is the
// pessimistic case for intern dedup (no folding possible) and the realistic
// stress case for the single-map layout, because every name produces
// exactly one map entry instead of up to three.
func benchSymbolSetUnique(n int) (static, dyn []elf.Symbol) {
	static = make([]elf.Symbol, 0, n/2)
	dyn = make([]elf.Symbol, 0, n/2)
	for i := 0; i < n/2; i++ {
		static = append(static, elf.Symbol{
			Name:  fmt.Sprintf("local_sym_%06d", i),
			Value: uint64(i + 1),
		})
	}
	for i := 0; i < n/2; i++ {
		if i%3 == 0 {
			dyn = append(dyn, elf.Symbol{
				Name:    fmt.Sprintf("import_sym_%06d", i),
				Library: "libc.so.6",
				Value:   0,
			})
		} else {
			dyn = append(dyn, elf.Symbol{
				Name:  fmt.Sprintf("export_sym_%06d", i),
				Value: uint64(i + 1),
			})
		}
	}
	return static, dyn
}

func BenchmarkParseSymbols(b *testing.B) {
	static, dyn := benchSymbolSetDeduped(4000)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		parseSymbols(static, dyn)
	}
}

func BenchmarkParseSymbolsUniqueNames(b *testing.B) {
	static, dyn := benchSymbolSetUnique(4000)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		parseSymbols(static, dyn)
	}
}

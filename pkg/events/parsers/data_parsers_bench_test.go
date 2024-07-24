package parsers

import "testing"

var parseMmapProtBenchTestArgs = []struct {
	rawValue uint64
}{
	{
		rawValue: PROT_NONE.Value(),
	},
	{
		rawValue: PROT_EXEC.Value(),
	},
	{
		rawValue: PROT_EXEC.Value() | PROT_READ.Value(),
	},
}

func BenchmarkParseMmapProt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for _, tt := range parseMmapProtBenchTestArgs {
			ParseMmapProt(tt.rawValue)
		}
	}
}

package proc

import "testing"

func BenchmarkGetAllProcNS(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GetAllProcNS(1)
	}
}

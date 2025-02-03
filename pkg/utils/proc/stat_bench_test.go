package proc

import (
	"os"
	"testing"

	"github.com/aquasecurity/tracee/pkg/utils/tests"
)

func Benchmark_newProcStat(b *testing.B) {
	file := tests.CreateTempFile(b, statContent)
	defer os.Remove(file.Name())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = newProcStat(file.Name(), statDefaultFields)
	}
}

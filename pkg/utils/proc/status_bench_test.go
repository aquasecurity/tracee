package proc

import (
	"os"
	"testing"

	"github.com/aquasecurity/tracee/pkg/utils/tests"
)

func Benchmark_newProcStatus(b *testing.B) {
	file := tests.CreateTempFile(b, statusContent)
	defer os.Remove(file.Name())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = newProcStatus(file.Name(), statusDefaultFields)
	}
}

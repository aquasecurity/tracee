package process

import (
	"os"
	"testing"

	"github.com/aquasecurity/tracee/common/tests"
)

// TestThread_PrintSizes prints the sizes of the structs used in the Thread type.
// Run it as DEBUG test to see the output.
func TestThread_PrintSizes(t *testing.T) {
	tests.PrintStructSizes(t, os.Stdout, Thread{})
}

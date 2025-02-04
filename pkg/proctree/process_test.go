package proctree

import (
	"os"
	"testing"

	"github.com/aquasecurity/tracee/pkg/utils/tests"
)

// TestProcess_PrintSizes prints the sizes of the structs used in the Process type.
// Run it as DEBUG test to see the output.
func TestProcess_PrintSizes(t *testing.T) {
	tests.PrintStructSizes(t, os.Stdout, Process{})
}

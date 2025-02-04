package proctree

import (
	"os"
	"testing"

	"github.com/aquasecurity/tracee/pkg/utils/tests"
)

// TestForkFeed_PrintSizes prints the sizes of the structs used in the ForkFeed type.
// Run it as DEBUG test to see the output.
func TestForkFeed_PrintSizes(t *testing.T) {
	forkFeed := ForkFeed{}
	tests.PrintStructSizes(t, os.Stdout, forkFeed)
}

// TestExecFeed_PrintSizes prints the sizes of the structs used in the ExecFeed type.
// Run it as DEBUG test to see the output.
func TestExecFeed_PrintSizes(t *testing.T) {
	execFeed := ExecFeed{}
	tests.PrintStructSizes(t, os.Stdout, execFeed)
}

// TestExitFeed_PrintSizes prints the sizes of the structs used in the ExitFeed type.
// Run it as DEBUG test to see the output.
func TestExitFeed_PrintSizes(t *testing.T) {
	exitFeed := ExitFeed{}
	tests.PrintStructSizes(t, os.Stdout, exitFeed)
}

package proctree

import (
	"os"
	"testing"

	"github.com/aquasecurity/tracee/pkg/utils/tests"
)

// TestTaskInfoFeed_PrintSizes prints the sizes of the structs used in the TaskInfoFeed type.
// Run it as DEBUG test to see the output.
func TestTaskInfoFeed_PrintSizes(t *testing.T) {
	taskInfo := TaskInfoFeed{}
	tests.PrintStructSizes(t, os.Stdout, taskInfo)
}

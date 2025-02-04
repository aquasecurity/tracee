package proctree

import (
	"os"
	"testing"

	"github.com/aquasecurity/tracee/pkg/utils/tests"
)

// TestFileInfoFeed_PrintSizes prints the sizes of the structs used in the FileInfoFeed type.
// Run it as DEBUG test to see the output.
func TestFileInfoFeed_PrintSizes(t *testing.T) {
	fileInfo := FileInfoFeed{}
	tests.PrintStructSizes(t, os.Stdout, fileInfo)
}

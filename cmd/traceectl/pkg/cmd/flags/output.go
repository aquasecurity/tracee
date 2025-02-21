package flags

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

type Output struct {
	Path   string
	Writer io.Writer
}

const OutputFlag = "output"

func PrepareOutput(cmd *cobra.Command, outputSlice string) (Output, error) {
	if strings.TrimSpace(outputSlice) == "stdout" {
		return Output{
			Path:   outputSlice,
			Writer: cmd.OutOrStdout(),
		}, nil
	}

	dir := filepath.Dir(outputSlice)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return Output{}, fmt.Errorf("failed to create directories for output file: %w", err)
	}

	file, err := os.OpenFile(outputSlice, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return Output{}, fmt.Errorf("failed to open output file: %w", err)
	}

	cmd.SetOut(file)
	cmd.SetErr(file)
	// Close the file after execution
	cmd.PersistentPostRun = func(cmd *cobra.Command, args []string) {
		file.Close()
	}
	return Output{
		Path:   outputSlice,
		Writer: cmd.OutOrStdout(),
	}, nil
}

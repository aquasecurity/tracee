package flags

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func PrepareOutput(cmd *cobra.Command, output string) error {
	if output != "" && output != "stdout" {
		if strings.TrimSpace(output) == "" {
			return fmt.Errorf("output file path is empty or invalid")
		}

		dir := filepath.Dir(output)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directories for output file: %v", err)
		}

		file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			return fmt.Errorf("failed to open output file: %v", err)
		}

		cmd.SetOut(file)
		cmd.SetErr(file)
		// Close the file after execution
		cmd.PersistentPostRun = func(cmd *cobra.Command, args []string) {
			file.Close()
		}
	}
	return nil
}

package flags

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func PrepareOutput(cmd *cobra.Command, output string) error {
	if (output != "") && (output != "stdout") {
		/// Validate the file path
		if output == "" || strings.TrimSpace(output) == "" {
			return fmt.Errorf("output file path is empty or invalid")
		}

		// Ensure parent directories exist
		dir := filepath.Dir(output)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directories for output file: %v", err)
		}

		// Create or open the file
		file, err := os.Create(output)
		if err != nil {
			return fmt.Errorf("failed to open output file: %v", err)
		}

		cmd.SetOut(file)
		cmd.SetErr(file)
		// Make sure to close the file after execution
		cmd.PersistentPostRun = func(cmd *cobra.Command, args []string) {
			file.Close()
		}
	}
	return nil
}

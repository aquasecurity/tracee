package formatter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

const (
	FormatJSON  = "json"
	FormatTable = "table"
	FormatGoTpl = "gotemplate"
)

var SupportedFormats = []string{FormatJSON, FormatTable, FormatGoTpl}

type Formatter struct {
	Format string
	Output string
	CMD    *cobra.Command
}

func New(format string, output string, cmd *cobra.Command) (*Formatter, error) {
	if !containsFormat(format) {
		return nil, fmt.Errorf("format %s is not supported", format)
	}
	if err := initOutput(cmd, output); err != nil {
		return nil, err
	}
	return &Formatter{
		Format: format,
		Output: output,
		CMD:    cmd,
	}, nil
}
func containsFormat(format string) bool {
	for _, f := range SupportedFormats {
		if f == format {
			return true
		}
	}
	return false
}
func initOutput(cmd *cobra.Command, output string) error {
	if (output != "") && (output != "stdout") {
		if output == "" || strings.TrimSpace(output) == "" {
			return fmt.Errorf("output file path is empty or invalid")
		}
		dir := filepath.Dir(output)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directories for output file: %v", err)
		}
		file, err := os.Create(output)
		if err != nil {
			return fmt.Errorf("failed to open output file: %v", err)
		}

		cmd.SetOut(file)
		cmd.SetErr(file)
		cmd.PersistentPostRun = func(cmd *cobra.Command, args []string) {
			file.Close()
		}
	}
	return nil
}

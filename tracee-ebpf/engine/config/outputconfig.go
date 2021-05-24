package config

import (
	"fmt"
	"strings"
)

type OutputConfig struct {
	Format         string
	OutPath        string
	ErrPath        string
	StackAddresses bool
	DetectSyscall  bool
	ExecEnv        bool
}

// Validate does static validation of the configuration
func (cfg *OutputConfig) Validate() error {
	if cfg.Format != "table" && cfg.Format != "table-verbose" && cfg.Format != "json" && cfg.Format != "gob" && !strings.HasPrefix(cfg.Format, "gotemplate=") {
		return fmt.Errorf("unrecognized output format: %s. Valid format values: 'table', 'table-verbose', 'json', 'gob' or 'gotemplate='. Use '--output help' for more info.", cfg.Format)
	}
	return nil
}

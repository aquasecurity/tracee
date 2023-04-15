package main

import (
	"os"

	"github.com/aquasecurity/tracee/cmd/tracee/cmd"
	"github.com/aquasecurity/tracee/pkg/logger"
)

func main() {
	logger.Init(logger.NewDefaultLoggingConfig())

	if err := cmd.Execute(); err != nil {
		logger.Fatalw("Execution", "error", err)
		os.Exit(1)
	}
}

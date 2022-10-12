package main

import (
	"os"

	"github.com/urfave/cli/v2"

	"github.com/aquasecurity/tracee/cmd/tracee/rules"
	"github.com/aquasecurity/tracee/pkg/logger"
)

func main() {
	app := &cli.App{
		Name:   "tracee-rules",
		Usage:  "a rule engine for runtime security",
		Action: rules.CLIAction(),
		Flags:  rules.CLIFlags(),
	}

	err := app.Run(os.Args)
	if err != nil {
		logger.Fatal("app", "error", err)
	}
}

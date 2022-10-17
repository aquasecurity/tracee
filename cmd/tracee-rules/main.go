package main

import (
	"os"

	"github.com/aquasecurity/tracee/cmd/tracee/rules"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "tracee-rules",
		Usage: "A rule engine for Runtime Security",
		//TODO: add version?
		//Version: version,
		Action: rules.CLIAction(),
		Flags:  rules.CLIFlags(),
	}

	err := app.Run(os.Args)

	if err != nil {
		logger.Fatal("app", "error", err)
	}
}

package main

import (
	"os"

	"github.com/aquasecurity/tracee/cmd/tracee/collect"
	"github.com/aquasecurity/tracee/cmd/tracee/rules"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/urfave/cli/v2"
)

var version string

func main() {
	app := &cli.App{
		Name:    "Tracee",
		Usage:   "Tracee cloud native runtime security",
		Version: version,
		Commands: []*cli.Command{
			{
				Name:   "collect",
				Usage:  "Collect OS events and syscalls using eBPF",
				Action: collect.CLIAction(version),
				Flags:  collect.CLIFlags(),
			},
			{
				Name:   "rules",
				Usage:  "A rule engine for runtime security",
				Action: rules.CLIAction(),
				Flags:  rules.CLIFlags(),
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		logger.Fatal("app", "error", err)
	}
}

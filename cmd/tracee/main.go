package main

import (
	"os"

	"github.com/aquasecurity/tracee/cmd/tracee/collect"
	"github.com/aquasecurity/tracee/cmd/tracee/rules"
	"github.com/aquasecurity/tracee/cmd/tracee/trace"
	"github.com/aquasecurity/tracee/pkg/logger"

	cli "github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "Tracee",
		Usage: "Tracee cloud native runtime security",
		Commands: []*cli.Command{
			&cli.Command{
				Name:   "collect",
				Usage:  "Collect OS events and syscalls using eBPF",
				Action: collect.CLIAction(),
				Flags:  collect.CLIFlags(),
			},
			&cli.Command{
				Name:   "rules",
				Usage:  "A rule engine for runtime security",
				Action: rules.CLIAction(),
				Flags:  rules.CLIFlags(),
			},
			&cli.Command{
				Name:   "trace",
				Usage:  "Start the collector and the rule engine",
				Action: trace.CLIAction(),
				Flags:  trace.CLIFlags(),
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		logger.Fatal("app", "error", err)
	}
}

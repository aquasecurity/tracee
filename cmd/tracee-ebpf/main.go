package main

import (
	"os"

	"github.com/aquasecurity/tracee/cmd/tracee/collect"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/urfave/cli/v2"
)

var version string

func main() {
	app := &cli.App{
		Name:    "Tracee",
		Usage:   "Trace OS events and syscalls using eBPF",
		Version: version,
		Action:  collect.CLIAction(version),
		Flags:   collect.CLIFlags(),
	}

	err := app.Run(os.Args)

	if err != nil {
		logger.Fatal("app", "error", err)
	}
}

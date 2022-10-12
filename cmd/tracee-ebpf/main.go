package main

import (
	"os"

	cli "github.com/urfave/cli/v2"

	"github.com/aquasecurity/tracee/cmd/tracee/collect"
	"github.com/aquasecurity/tracee/pkg/logger"
)

var version string

func main() {
	app := &cli.App{
		Name:    "Tracee",
		Usage:   "Trace OS events and syscalls using eBPF",
		Version: version,
		Action:  collect.CLIAction(),
		Flags:   collect.CLIFlags(),
	}

	err := app.Run(os.Args)
	if err != nil {
		logger.Fatal("app", "error", err)
	}
}

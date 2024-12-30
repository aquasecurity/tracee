package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	cli "github.com/urfave/cli/v2"

	"github.com/aquasecurity/tracee/pkg/cmd"
	"github.com/aquasecurity/tracee/pkg/cmd/flags"

	// "github.com/aquasecurity/tracee/pkg/cmd/flags/server"
	"github.com/aquasecurity/tracee/pkg/cmd/initialize"
	"github.com/aquasecurity/tracee/pkg/cmd/urfave"
	"github.com/aquasecurity/tracee/pkg/logger"
)

var version string

func main() {
	app := &cli.App{
		Name:    "Tracee",
		Usage:   "Trace OS events and syscalls using eBPF",
		Version: version,
		Action: func(c *cli.Context) error {
			if c.NArg() > 0 {
				return cli.ShowAppHelp(c) // no args, only flags supported
			}

			// Logger Setup
			logger.Init(logger.NewDefaultLoggingConfig())

			flags.PrintAndExitIfHelp(c)

			if c.Bool("list") {
				cmd.PrintEventList(false, false) // list events
				return nil
			}
			initialize.SetLibbpfgoCallbacks()

			runner, err := urfave.GetTraceeRunner(c, version)
			if err != nil {
				return err
			}

			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			return runner.Run(ctx)
		},
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "list",
				Aliases: []string{"l"},
				Value:   false,
				Usage:   "list traceable events",
			},
			&cli.StringSliceFlag{
				Name:    "scope",
				Aliases: []string{"s"},
				Value:   nil,
				Usage:   "select workloads to trace by defining filter expressions. run '--scope help' for more info.",
			},
			&cli.StringSliceFlag{
				Name:    "events",
				Aliases: []string{"e"},
				Usage:   "select events to trace and filter events. run '--events help' for more info.",
			},
			&cli.StringSliceFlag{
				Name:    "capture",
				Aliases: []string{"c"},
				Value:   nil,
				Usage:   "capture artifacts that were written, executed or found to be suspicious. run '--capture help' for more info.",
			},
			&cli.StringSliceFlag{
				Name:    "capabilities",
				Aliases: []string{"caps"},
				Value:   nil,
				Usage:   "define capabilities for tracee to run with. run '--capabilities help' for more info.",
			},
			&cli.StringSliceFlag{
				Name:    "output",
				Aliases: []string{"o"},
				Value:   cli.NewStringSlice("format:table"),
				Usage:   "control how and where output is printed. run '--output help' for more info.",
			},
			&cli.StringSliceFlag{
				Name:    "cache",
				Aliases: []string{"a"},
				Value:   cli.NewStringSlice("none"),
				Usage:   "control event caching queues. run '--cache help' for more info.",
			},
			&cli.StringSliceFlag{
				Name:    "proctree",
				Aliases: []string{"t"},
				Value:   cli.NewStringSlice("none"),
				Usage:   "process tree options. run '--proctree help' for more info.",
			},
			&cli.StringSliceFlag{
				Name:  "dnscache",
				Value: cli.NewStringSlice("none"),
				Usage: "dns cache options. run '--dnscache help' for more info",
			},
			&cli.StringSliceFlag{
				Name:  "cri",
				Usage: "define connected container runtimes. run '--cri help' for more info.",
				Value: cli.NewStringSlice(),
			},
			&cli.IntFlag{
				Name:    "perf-buffer-size",
				Aliases: []string{"b"},
				Value:   1024, // 4 MB of contiguous pages
				Usage:   "size, in pages, of the internal perf ring buffer used to submit events from the kernel",
			},
			&cli.IntFlag{
				Name:  "blob-perf-buffer-size",
				Value: 1024, // 4 MB of contiguous pages
				Usage: "size, in pages, of the internal perf ring buffer used to send blobs from the kernel",
			},
			&cli.IntFlag{
				Name:  "pipeline-channel-size",
				Value: 10000,
				Usage: "size, in event objects, of each pipeline stage's output channel",
			},
			&cli.StringFlag{
				Name:  "install-path",
				Value: "/tmp/tracee",
				Usage: "path where tracee will install or lookup it's resources",
			},
			// &cli.BoolFlag{
			// 	Name:  server.MetricsEndpointFlag,
			// 	Usage: "enable metrics endpoint",
			// 	Value: false,
			// },
			// &cli.BoolFlag{
			// 	Name:  server.HealthzEndpointFlag,
			// 	Usage: "enable healthz endpoint",
			// 	Value: false,
			// },
			// &cli.BoolFlag{
			// 	Name:  server.PProfEndpointFlag,
			// 	Usage: "enable pprof endpoints",
			// 	Value: false,
			// },
			// &cli.BoolFlag{
			// 	Name:  server.PyroscopeAgentFlag,
			// 	Usage: "enable pyroscope agent",
			// 	Value: false,
			// },
			// &cli.StringFlag{
			// 	Name:  server.HTTPListenEndpointFlag,
			// 	Usage: "listening address of the metrics endpoint server",
			// 	Value: ":3366",
			// },
			&cli.BoolFlag{
				Name:  "no-containers",
				Usage: "disable container info enrichment to events. safeguard option.",
			},
			&cli.StringSliceFlag{
				Name:  "log",
				Usage: "logger option. run '--log help' for more info.",
				Value: cli.NewStringSlice("info"),
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		logger.Fatalw("App", "error", err)
	}
}

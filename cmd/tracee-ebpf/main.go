package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/tracee/pkg/cmd"
	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/cmd/flags/server"
	"github.com/aquasecurity/tracee/pkg/cmd/urfave"
	"github.com/aquasecurity/tracee/pkg/logger"

	cli "github.com/urfave/cli/v2"
)

func init() {
	// Avoiding to override package-level logger
	// when it's already set by logger environment variables
	if !logger.IsSetFromEnv() {
		// Logger Setup
		logger.Init(
			&logger.LoggerConfig{
				Writer:    os.Stderr,
				Level:     logger.InfoLevel,
				Encoder:   logger.NewJSONEncoder(logger.NewProductionConfig().EncoderConfig),
				Aggregate: false,
			},
		)
	}

	// Set libbpfgo logging callbacks
	libbpfgo.SetLoggerCbs(libbpfgo.Callbacks{
		Log: func(libLevel int, msg string, keyValues ...interface{}) {
			lvl := logger.ErrorLevel

			switch libLevel {
			case libbpfgo.LibbpfWarnLevel:
				lvl = logger.WarnLevel
			case libbpfgo.LibbpfInfoLevel:
				lvl = logger.InfoLevel
			case libbpfgo.LibbpfDebugLevel:
				lvl = logger.DebugLevel
			}

			logger.Log(lvl, false, msg, keyValues...)
		},
		LogFilters: []func(libLevel int, msg string) bool{
			libbpfgo.LogFilterLevel,
			libbpfgo.LogFilterOutput,
		},
	})
}

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

			flags.PrintAndExitIfHelp(c)

			if c.Bool("list") {
				cmd.PrintEventList(false) // list events
				return nil
			}

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
				Usage:   "list tracable events",
			},
			&cli.StringSliceFlag{
				Name:    "trace",
				Aliases: []string{"t"},
				Value:   nil,
				Usage:   "select events to trace by defining trace expressions. run '--trace help' for more info.",
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
				Name:  "crs",
				Usage: "define connected container runtimes. run '--crs help' for more info.",
				Value: cli.NewStringSlice(),
			},
			&cli.IntFlag{
				Name:    "perf-buffer-size",
				Aliases: []string{"b"},
				Value:   1024, // 4 MB of contigous pages
				Usage:   "size, in pages, of the internal perf ring buffer used to submit events from the kernel",
			},
			&cli.IntFlag{
				Name:  "blob-perf-buffer-size",
				Value: 1024, // 4 MB of contigous pages
				Usage: "size, in pages, of the internal perf ring buffer used to send blobs from the kernel",
			},
			&cli.StringFlag{
				Name:  "install-path",
				Value: "/tmp/tracee",
				Usage: "path where tracee will install or lookup it's resources",
			},
			&cli.BoolFlag{
				Name:  server.MetricsEndpointFlag,
				Usage: "enable metrics endpoint",
				Value: false,
			},
			&cli.BoolFlag{
				Name:  server.HealthzEndpointFlag,
				Usage: "enable healthz endpoint",
				Value: false,
			},
			&cli.BoolFlag{
				Name:  server.PProfEndpointFlag,
				Usage: "enable pprof endpoints",
				Value: false,
			},
			&cli.StringFlag{
				Name:  server.ListenEndpointFlag,
				Usage: "listening address of the metrics endpoint server",
				Value: ":3366",
			},
			&cli.BoolFlag{
				Name:  "containers",
				Usage: "enable container info enrichment to events. this feature is experimental and may cause unexpected behavior in the pipeline",
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
		logger.Fatal("app", "error", err)
	}
}

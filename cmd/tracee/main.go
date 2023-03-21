package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"

	cli "github.com/urfave/cli/v2"

	"github.com/aquasecurity/tracee/pkg/cmd"
	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/cmd/flags/server"
	"github.com/aquasecurity/tracee/pkg/cmd/initialize"
	"github.com/aquasecurity/tracee/pkg/cmd/urfave"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/signatures/engine"
	"github.com/aquasecurity/tracee/pkg/signatures/signature"
	"github.com/aquasecurity/tracee/types/detect"
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

			logger.Init(logger.NewDefaultLoggingConfig())

			flags.PrintAndExitIfHelp(c, true)

			// Rego command line flags

			if c.StringSlice("policy") != nil && c.StringSlice("filter") != nil {
				return errors.New("policy and filter flags cannot be used together")
			}

			rego, err := flags.PrepareRego(c.StringSlice("rego"))
			if err != nil {
				return err
			}

			sigs, err := signature.Find(
				rego.RuntimeTarget,
				rego.PartialEval,
				c.String("signatures-dir"),
				nil,
				rego.AIO,
			)
			if err != nil {
				return err
			}

			createEventsFromSignatures(events.StartSignatureID, sigs)

			if c.Bool("list") {
				cmd.PrintEventList(true) // list events
				return nil
			}

			initialize.SetLibbpfgoCallbacks()

			runner, err := urfave.GetTraceeRunner(c, version, true)
			if err != nil {
				return err
			}

			// parse arguments must be enabled if the rule engine is part of the pipeline
			runner.TraceeConfig.Output.ParseArguments = true

			runner.TraceeConfig.EngineConfig = engine.Config{
				Enabled:    true,
				Signatures: sigs,
				// This used to be a flag, we have removed the flag from this binary to test
				// if users do use it or not.
				SignatureBufferSize: 1000,
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
				Name:    "policy",
				Aliases: []string{"p"},
				Usage:   "path to a policy or directory with policies",
			},
			&cli.StringSliceFlag{
				Name:    "filter",
				Aliases: []string{"f"},
				Value:   nil,
				Usage:   "select events to trace by defining filter expressions. run '--filter help' for more info.",
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
				Value:   cli.NewStringSlice("table"),
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
				Value:   1024, // 4 MB of contiguous pages
				Usage:   "size, in pages, of the internal perf ring buffer used to submit events from the kernel",
			},
			&cli.IntFlag{
				Name:  "blob-perf-buffer-size",
				Value: 1024, // 4 MB of contiguous pages
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
			&cli.BoolFlag{
				Name:  server.PyroscopeAgentFlag,
				Usage: "enable pyroscope agent",
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

			// TODO: add webhook

			// signature events
			&cli.StringFlag{
				Name:  "signatures-dir",
				Usage: "directory where to search for signatures in CEL (.yaml), OPA (.rego), and Go plugin (.so) formats",
			},
			&cli.StringSliceFlag{
				Name:  "rego",
				Usage: "control event rego settings. run '--rego help' for more info.",
				Value: cli.NewStringSlice(),
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

func createEventsFromSignatures(startId events.ID, sigs []detect.Signature) {
	id := startId

	for _, s := range sigs {
		m, err := s.GetMetadata()
		if err != nil {
			logger.Errorw("Failed to load event", "error", err)
			continue
		}

		selectedEvents, err := s.GetSelectedEvents()
		if err != nil {
			logger.Errorw("Failed to load event", "error", err)
			continue
		}

		dependencies := make([]events.ID, 0)

		for _, s := range selectedEvents {
			eventID, found := events.Definitions.GetID(s.Name)
			if !found {
				logger.Errorw("Failed to load event dependency", "event", s.Name)
				continue
			}

			dependencies = append(dependencies, eventID)
		}

		event := events.NewEventDefinition(m.EventName, []string{"signatures", "default"}, dependencies)

		err = events.Definitions.Add(id, event)
		if err != nil {
			logger.Errorw("Failed to add event definition", "error", err)
			continue
		}

		id++
	}
}

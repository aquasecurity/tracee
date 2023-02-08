package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/cmd/flags/server"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/rules/engine"
	"github.com/aquasecurity/tracee/pkg/rules/signature"
	"github.com/aquasecurity/tracee/types/detect"

	"github.com/open-policy-agent/opa/compile"
	"github.com/urfave/cli/v2"
	"kernel.org/pub/linux/libs/security/libcap/cap"
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
}

const (
	signatureBufferFlag = "sig-buffer"
)

func main() {
	app := &cli.App{
		Name:  "tracee-rules",
		Usage: "A rule engine for Runtime Security",
		Action: func(c *cli.Context) error {

			// Capabilities command line flags

			err := capabilities.Initialize(c.Bool("allcaps"))
			if err != nil {
				return err
			}

			if c.NumFlags() == 0 {
				cli.ShowAppHelp(c)
				return errors.New("no flags specified")
			}

			var target string
			switch strings.ToLower(c.String("rego-runtime-target")) {
			case "wasm":
				return errors.New("target unsupported: wasm")
			case "rego":
				target = compile.TargetRego
			default:
				return fmt.Errorf("invalid target specified: %s", strings.ToLower(c.String("rego-runtime-target")))
			}

			sigs, err := signature.Find(
				target,
				c.Bool("rego-partial-eval"),
				c.String("rules-dir"),
				c.StringSlice("rules"),
				c.Bool("rego-aio"),
			)
			if err != nil {
				return err
			}

			var loadedSigIDs []string
			capabilities.GetInstance().Requested(
				func() error {
					for _, s := range sigs {
						m, err := s.GetMetadata()
						if err != nil {
							logger.Error("Failed to load signature", "error", err)
							continue
						}
						loadedSigIDs = append(loadedSigIDs, m.ID)
					}
					return nil
				},
				cap.DAC_OVERRIDE,
			)
			if c.Bool("list-events") {
				listEvents(os.Stdout, sigs)
				return nil
			}

			logger.Info("Signatures loaded", "total", len(loadedSigIDs), "signatures", loadedSigIDs)

			if c.Bool("list") {
				listSigs(os.Stdout, sigs)
				return nil
			}

			var inputs engine.EventSources

			opts, err := parseTraceeInputOptions(c.StringSlice("input-tracee"))
			if err == errHelp {
				printHelp()
				return nil
			}
			if err != nil {
				return err
			}

			inputs.Tracee, err = setupTraceeInputSource(opts)
			if err != nil {
				return err
			}

			output, err := setupOutput(
				os.Stdout,
				c.String("webhook"),
				c.String("webhook-template"),
				c.String("webhook-content-type"),
				c.String("output-template"),
			)
			if err != nil {
				return err
			}

			config := engine.Config{
				SignatureBufferSize: c.Uint(signatureBufferFlag),
				Signatures:          sigs,
			}
			e, err := engine.NewEngine(config, inputs, output)
			if err != nil {
				return fmt.Errorf("constructing engine: %w", err)
			}

			httpServer, err := server.PrepareServer(
				c.String(server.ListenEndpointFlag),
				c.Bool(server.MetricsEndpointFlag),
				c.Bool(server.HealthzEndpointFlag),
				c.Bool(server.PProfEndpointFlag),
			)

			if err != nil {
				return err
			}

			if httpServer != nil {
				go httpServer.Start()
			}

			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			e.Start(ctx)

			return nil
		},
		Flags: []cli.Flag{
			&cli.StringSliceFlag{
				Name:  "rules",
				Usage: "select which rules to load. Specify multiple rules by repeating this flag. Use --list for rules to select from",
			},
			&cli.StringFlag{
				Name:  "rules-dir",
				Usage: "directory where to search for rules in CEL (.yaml), OPA (.rego), and Go plugin (.so) formats",
			},
			&cli.BoolFlag{
				Name:  "rego-partial-eval",
				Usage: "enable partial evaluation of rego rules",
			},
			&cli.BoolFlag{
				Name:  "list",
				Usage: "print all available rules",
			},
			&cli.StringFlag{
				Name:  "webhook",
				Usage: "HTTP endpoint to call for every match",
			},
			&cli.StringFlag{
				Name:  "webhook-template",
				Usage: "path to a gotemplate for formatting webhook output",
			},
			&cli.StringFlag{
				Name:  "webhook-content-type",
				Usage: "content type of the template in use. Recommended if using --webhook-template",
			},
			&cli.StringSliceFlag{
				Name:  "input-tracee",
				Usage: "configure tracee-ebpf as input source. see '--input-tracee help' for more info",
			},
			&cli.StringFlag{
				Name:  "output-template",
				Usage: "configure output format via templates. Usage: --output-template=path/to/my.tmpl",
			},
			&cli.BoolFlag{
				Name:  server.PProfEndpointFlag,
				Usage: "enable pprof endpoints",
				Value: false,
			},
			&cli.BoolFlag{
				Name:  "rego-aio",
				Usage: "compile rego signatures altogether as an aggregate policy. By default each signature is compiled separately.",
			},
			&cli.StringFlag{
				Name:  "rego-runtime-target",
				Usage: "select which runtime target to use for evaluation of rego rules: rego, wasm",
				Value: "rego",
			},
			&cli.BoolFlag{
				Name:  "list-events",
				Usage: "print a list of events that currently loaded signatures require",
			},
			&cli.UintFlag{
				Name:  signatureBufferFlag,
				Usage: "size of the event channel's buffer consumed by signatures",
				Value: 1000,
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
			&cli.StringFlag{
				Name:  server.ListenEndpointFlag,
				Usage: "listening address of the metrics endpoint server",
				Value: ":4466",
			},
			&cli.BoolFlag{
				Name:  "allcaps",
				Value: false,
				Usage: "allow tracee-rules to run with all capabilities (use with caution)",
			},
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		logger.Fatal("app", "error", err)
	}
}

func listSigs(w io.Writer, sigs []detect.Signature) {
	fmt.Fprintf(w, "%-10s %-35s %s %s\n", "ID", "NAME", "VERSION", "DESCRIPTION")
	for _, sig := range sigs {
		meta, err := sig.GetMetadata()
		if err != nil {
			continue
		}
		fmt.Fprintf(w, "%-10s %-35s %-7s %s\n", meta.ID, meta.Name, meta.Version, meta.Description)
	}
}

func listEvents(w io.Writer, sigs []detect.Signature) {
	m := make(map[string]struct{})
	for _, sig := range sigs {
		es, _ := sig.GetSelectedEvents()
		for _, e := range es {
			if _, ok := m[e.Name]; !ok {
				m[e.Name] = struct{}{}
			}
		}
	}

	var events []string
	for k := range m {
		events = append(events, k)
	}

	sort.Slice(events, func(i, j int) bool { return events[i] < events[j] })
	fmt.Fprintln(w, strings.Join(events, ","))
}

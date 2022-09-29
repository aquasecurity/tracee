package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/rules/engine"
	"github.com/aquasecurity/tracee/pkg/server"
	"github.com/aquasecurity/tracee/types/detect"

	"github.com/open-policy-agent/opa/compile"
	"github.com/urfave/cli/v2"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

const (
	signatureBufferFlag       = "sig-buffer"
	allowHighCapabilitiesFlag = "allow-high-capabilities"
)

func main() {
	app := &cli.App{
		Name:  "tracee-rules",
		Usage: "A rule engine for Runtime Security",
		Action: func(c *cli.Context) error {
			if c.NumFlags() == 0 {
				cli.ShowAppHelp(c)
				return errors.New("no flags specified")
			}

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

			err := dropCapabilities()
			if err != nil {
				if !c.Bool(allowHighCapabilitiesFlag) {
					return fmt.Errorf("%w - to avoid this error use the --%s flag", err, allowHighCapabilitiesFlag)
				}

				logger.Error("capabilities dropping failed", "error", err)
				logger.Info("continue with high capabilities according to the configuration")
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

			sigs, err := getSignatures(
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
			for _, s := range sigs {
				m, err := s.GetMetadata()
				if err != nil {
					logger.Error("failed to load signature", "error", err)
					continue
				}
				loadedSigIDs = append(loadedSigIDs, m.ID)
			}

			if c.Bool("list-events") {
				listEvents(os.Stdout, sigs)
				return nil
			}

			fmt.Printf("Loaded %d signature(s): %s\n", len(loadedSigIDs), loadedSigIDs)

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
			}
			e, err := engine.NewEngine(sigs, inputs, output, os.Stderr, config)
			if err != nil {
				return fmt.Errorf("constructing engine: %w", err)
			}

			if server.ShouldStart(c) {
				httpServer := server.New(c.String(server.ListenEndpointFlag), false)

				if c.Bool(server.MetricsEndpointFlag) {
					err := e.Stats().RegisterPrometheus()
					if err != nil {
						logger.Error("registering prometheus metrics", "error", err)
					} else {
						httpServer.EnableMetricsEndpoint()
					}
				}

				if c.Bool(server.HealthzEndpointFlag) {
					httpServer.EnableHealthzEndpoint()
				}

				if c.Bool(server.PProfEndpointFlag) {
					httpServer.EnablePProfEndpoint()
				}

				go httpServer.Start()
			}

			e.Start(sigHandler())

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
				Usage: "enables pprof endpoints",
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
				Name:    allowHighCapabilitiesFlag,
				Aliases: []string{"ahc"},
				Usage:   "allow tracee-rules to run with high capabilities, in case that capabilities dropping fails",
				Value:   false,
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

func sigHandler() chan bool {
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		done <- true
	}()
	return done
}

// dropCapabilities drop all capabilities from the process
// The function also tries to drop the capabilities bounding set, but it won't work if CAP_SETPCAP is not available.
func dropCapabilities() error {
	return capabilities.DropUnrequired([]cap.Value{})
}

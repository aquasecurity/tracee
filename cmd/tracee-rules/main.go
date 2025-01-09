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

	"github.com/urfave/cli/v2"
	"kernel.org/pub/linux/libs/security/libcap/cap"

	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/cmd/flags/server"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/signatures/engine"
	"github.com/aquasecurity/tracee/pkg/signatures/signature"
	"github.com/aquasecurity/tracee/types/detect"
)

const (
	signatureBufferFlag = "sig-buffer"
)

func main() {
	app := &cli.App{
		Name:  "tracee-rules",
		Usage: "A rule engine for Runtime Security",
		Action: func(c *cli.Context) error {
			// Logger Setup
			logger.Init(logger.NewDefaultLoggingConfig())

			// Capabilities command line flags

			if c.NumFlags() == 0 {
				if err := cli.ShowAppHelp(c); err != nil {
					logger.Errorw("Failed to show app help", "error", err)
				}
				return errors.New("no flags specified")
			}

			var rulesDir []string
			if c.String("rules-dir") != "" {
				rulesDir = []string{c.String("rules-dir")}
			}

			sigs, _, err := signature.Find(
				rulesDir,
				c.StringSlice("rules"),
			)
			if err != nil {
				return err
			}

			// can't drop privileges before this point due to signature.Find(),
			// orelse we would have to raise capabilities in Find() and it can't
			// be done in the single binary case (capabilities initialization
			// happens after Find() is called) in that case.

			bypass := c.Bool("allcaps") || !isRoot()
			err = capabilities.Initialize(
				capabilities.Config{
					Bypass: bypass,
				},
			)
			if err != nil {
				return err
			}

			var loadedSigIDs []string
			err = capabilities.GetInstance().Specific(
				func() error {
					for _, s := range sigs {
						m, err := s.GetMetadata()
						if err != nil {
							logger.Errorw("Failed to load signature", "error", err)
							continue
						}
						loadedSigIDs = append(loadedSigIDs, m.ID)
					}
					return nil
				},
				cap.DAC_OVERRIDE,
			)
			if err != nil {
				logger.Errorw("Requested capabilities", "error", err)
			}

			if c.Bool("list-events") {
				listEvents(os.Stdout, sigs)
				return nil
			}

			logger.Infow("Signatures loaded", "total", len(loadedSigIDs), "signatures", loadedSigIDs)

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
				DataSources:         []detect.DataSource{},
			}
			e, err := engine.NewEngine(config, inputs, output)
			if err != nil {
				return fmt.Errorf("constructing engine: %w", err)
			}

			// httpServer, err := server.PrepareHTTPServer(
			// 	c.String(server.HTTPListenEndpointFlag),
			// 	c.Bool(server.MetricsEndpointFlag),
			// 	c.Bool(server.HealthzEndpointFlag),
			// 	c.Bool(server.PProfEndpointFlag),
			// 	c.Bool(server.PyroscopeAgentFlag),
			// )
			if err != nil {
				return err
			}

			err = e.Init()
			if err != nil {
				return err
			}

			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			// if httpServer != nil {
			// 	go httpServer.Start(ctx)
			// }

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
				Usage: "directory where to search for rules in Go plugin (.so) format",
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
				Name:  server.HTTPServer + "." + server.PProfEndpointFlag,
				Usage: "enable pprof endpoints",
				Value: false,
			},
			&cli.BoolFlag{
				Name:  server.HTTPServer + "." + server.PyroscopeAgentEndpointFlag,
				Usage: "enable pyroscope agent",
				Value: false,
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
				Name:  server.HTTPServer + "." + server.MetricsEndpointFlag,
				Usage: "enable metrics endpoint",
				Value: false,
			},
			&cli.BoolFlag{
				Name:  server.HTTPServer + "." + server.HealthzEndpointFlag,
				Usage: "enable healthz endpoint",
				Value: false,
			},
			&cli.StringFlag{
				Name:  server.HTTPServer + "." + server.ListenEndpointFlag,
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
		logger.Fatalw("App", "error", err)
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

func isRoot() bool {
	return os.Geteuid() == 0
}

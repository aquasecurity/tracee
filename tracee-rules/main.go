package main

import (
	"errors"
	"fmt"
	"github.com/aquasecurity/tracee/tracee-rules/signatures/helpers"
	"io"
	"log"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aquasecurity/tracee/tracee-rules/engine"
	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/urfave/cli/v2"
)

type Clock interface {
	Now() time.Time
}

type realClock struct {
}

func (realClock) Now() time.Time {
	return time.Now()
}

func main() {
	app := &cli.App{
		Name:  "tracee-rules",
		Usage: "A rule engine for Runtime Security",
		Action: func(c *cli.Context) error {

			if c.NumFlags() == 0 {
				cli.ShowAppHelp(c)
				return errors.New("no flags specified")
			}

			if c.Bool("pprof") {
				mux := http.NewServeMux()
				mux.HandleFunc("/debug/pprof/", pprof.Index)
				mux.Handle("/debug/pprof/allocs", pprof.Handler("allocs"))
				mux.Handle("/debug/pprof/block", pprof.Handler("block"))
				mux.Handle("/debug/pprof/heap", pprof.Handler("heap"))
				mux.Handle("/debug/pprof/mutex", pprof.Handler("mutex"))
				mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
				mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
				mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
				mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
				go func() {
					addr := c.String("pprof-addr")
					fmt.Fprintf(os.Stdout, "Serving pprof endpoints at %s\n", addr)
					if err := http.ListenAndServe(addr, mux); err != http.ErrServerClosed {
						fmt.Fprintf(os.Stderr, "Error serving pprof endpoints: %v\n", err)
					}
				}()
			}

			sigs, err := getSignatures(c.String("rules-dir"), c.StringSlice("rules"))
			if err != nil {
				return err
			}

			var loadedSigIDs []string
			for _, s := range sigs {
				m, err := s.GetMetadata()
				if err != nil {
					fmt.Println("failed to load signature: ", err)
					continue
				}
				loadedSigIDs = append(loadedSigIDs, m.ID)
			}
			fmt.Println("Loaded signature(s): ", loadedSigIDs)

			if c.Bool("list") {
				return listSigs(os.Stdout, sigs)
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

			if inputs == (engine.EventSources{}) {
				return err
			}

			err = helpers.InitSystemInfo(c.String("system-info-file"))
			if err != nil {
				fmt.Println("failed to load system info file: ", err)
			}

			output, err := setupOutput(os.Stdout, c.String("webhook"), c.String("webhook-template"), c.String("webhook-content-type"), c.String("output-template"))
			if err != nil {
				return err
			}
			e, err := engine.NewEngine(sigs, inputs, output, os.Stderr)
			if err != nil {
				return fmt.Errorf("constructing engine: %w", err)
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
				Usage: "directory where to search for rules in OPA (.rego) or Go plugin (.so) formats",
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
				Name:  "pprof",
				Usage: "enables pprof endpoints",
			},
			&cli.StringFlag{
				Name:  "pprof-addr",
				Usage: "listening address of the pprof endpoints server",
				Value: ":7777",
			},
			&cli.StringFlag{
				Name:  "system-info-file",
				Usage: "configure usage of given file as system information of the machine tracee-ebpf have run from",
				Value: "./system_info.json",
			},
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func listSigs(w io.Writer, sigs []types.Signature) error {
	fmt.Fprintf(w, "%-10s %-35s %s %s\n", "ID", "NAME", "VERSION", "DESCRIPTION")
	for _, sig := range sigs {
		meta, err := sig.GetMetadata()
		if err != nil {
			continue
		}
		fmt.Fprintf(w, "%-10s %-35s %-7s %s\n", meta.ID, meta.Name, meta.Version, meta.Description)
	}
	return nil
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

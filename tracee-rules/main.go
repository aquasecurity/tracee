package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/aquasecurity/tracee/tracee-rules/engine"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "tracee-rules",
		Usage: "A rule engine for Runtime Security",
		Action: func(c *cli.Context) error {
			if c.NumFlags() == 0 {
				cli.ShowAppHelp(c)
				return nil
			}
			sigs, err := getSignatures(c.String("rules-dir"), c.StringSlice("rules"))
			if err != nil {
				return err
			}
			if c.Bool("list") {
				for _, sig := range sigs {
					meta, err := sig.GetMetadata()
					if err != nil {
						continue
					}
					fmt.Printf("%s: %s\n", meta.Name, meta.Description)
				}
				return nil
			}
			var inputs engine.EventSources
			if c.IsSet("input-tracee") {
				opts, err := parseTraceeInputOptions(c.StringSlice("input-tracee"))
				if err == helpErr {
					printHelp()
					return nil
				}
				if err != nil {
					return err
				}
				inputs.Tracee, err = setupInputSource(opts)
				if err != nil {
					return err
				}
			}
			if inputs == (engine.EventSources{}) {
				return err
			}
			output, err := setupOutput(c.String("webhook"))
			if err != nil {
				return err
			}
			e := engine.NewEngine(sigs, inputs, output, os.Stderr)
			e.Start(sigHandler())
			return nil
		},
		Flags: []cli.Flag{
			&cli.StringSliceFlag{
				Name:  "rules",
				Usage: "select which rules to load as a comma seperated list, use --list for rules to select from",
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
			&cli.StringSliceFlag{
				Name:  "input-tracee",
				Usage: "specify various key:value pairs for input options from tracee-ebpf, use '--input-tracee help' for more info",
			},
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
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

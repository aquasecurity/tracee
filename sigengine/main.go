package main

import (
	"fmt"
	"log"
	"os"

	"github.com/urfave/cli/v2"
	"sigengine/sigengine"
	_ "sigengine/signatures/go"
)

func main() {
	app := &cli.App{
		Name:  "Sigengine",
		Usage: "Signatures engine",
		Action: func(c *cli.Context) error {
			cfg := sigengine.SignaturesConfig{
				RequestedSigs: c.StringSlice("signatures"),
				InputSources:  c.StringSlice("input"),
				Severity:      "debug", // todo: use enum and let user choose
				PrintSigList:  c.Bool("list"),
			}
			e, err := sigengine.New(cfg)
			if err != nil {
				// e is being closed internally
				return fmt.Errorf("error creating Sigengine: %v", err)
			}
			if cfg.PrintSigList {
				return nil
			}

			return e.Run()
		},
		Flags: []cli.Flag{
			&cli.StringSliceFlag{
				Name:    "signatures",
				Aliases: []string{"s"},
				Value:   nil,
				Usage:   "only use the specified signatures. use this flag multiple times to choose multiple signatures",
			},
			&cli.BoolFlag{
				Name:    "list",
				Aliases: []string{"l"},
				Value:   false,
				Usage:   "list available signatures",
			},
			&cli.StringSliceFlag{
				Name:    "input",
				Aliases: []string{"i"},
				Usage:   "select input sources",
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

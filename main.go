package main

import (
	"fmt"
	"log"
	"os"
	"github.com/urfave/cli/v2"
	"github.com/aquasecurity/tracee/tracee"
)

func main() {
	app := &cli.App{
		Name:  "Tracee",
		Usage: "Trace OS events and syscalls using eBPF",
		Action: func(c *cli.Context) error {
			t, err := tracee.New(tracee.TraceConfig{ 
				OutputFormat: c.String("output"),
			})
			if err != nil{
				// t is being closed internally
				return fmt.Errorf("error creating Tracee: %v", err)
			}
			return t.Run()
		},
		Flags: []cli.Flag {
      &cli.StringFlag{
				Name: "output",
				Aliases: []string{"o"},
				Value: "table",
        Usage: "output format: table (default)/json",
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
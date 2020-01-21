package main

import (
	"fmt"
	"strings"
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
			if c.Bool("list") {
				printList()
				return nil
			}
			cfg, err := tracee.NewConfig(
				c.StringSlice("events-to-trace"),
				c.Bool("container"),
				c.Bool("detect-original-syscall"),
				c.String("output"),
			)
			if err != nil{
				return fmt.Errorf("error creating Tracee config: %v", err)
			}
			t, err := tracee.New(*cfg)
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
			&cli.StringSliceFlag{
				Name: "events-to-trace",
				Aliases: []string{"e"},
				Value: nil,
        Usage: "trace only the specified events and syscalls",
			},
			&cli.BoolFlag{
				Name: "list",
				Aliases: []string{"l"},
				Value: false,
        Usage: "just list tracable events",
			},
			&cli.BoolFlag{
				Name: "container",
				Aliases: []string{"c"},
				Value: false,
        Usage: "trace only containers",
			},
			&cli.BoolFlag{
				Name: "detect-original-syscall",
				Value: false,
        Usage: "when tracing kernel functions which are not syscalls (such as cap_capable), detect and show the original syscall that called that function",
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func printList() {
	const sep = ", "
	var b strings.Builder
	for sc := range tracee.Syscalls {
		fmt.Fprintf(&b, "%s%s", sc, sep)
	}
	fmt.Println("System calls:")
	fmt.Println(strings.TrimSuffix(b.String(), sep))
	b.Reset()
	fmt.Println()
	for se := range tracee.Sysevents {
		fmt.Fprintf(&b, "%s%s", se, sep)
	}
	fmt.Println("System events:")
	fmt.Println(strings.TrimSuffix(b.String(), sep))
}
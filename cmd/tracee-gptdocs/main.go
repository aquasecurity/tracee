package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/urfave/cli/v2"

	"github.com/aquasecurity/tracee/pkg/cmd"
)

const (
	openAIKey   = "openaikey"
	temperature = "temperature"
	maxTokens   = "maxtokens"
	givenEvents = "events"
)

func main() {
	app := cli.App{
		Name:  "tracee-gptdocs",
		Usage: "Automated event documentation for tracee",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  openAIKey,
				Usage: "OpenAI API secret key",
				Value: "",
			},
			&cli.Float64Flag{
				Name:  temperature,
				Usage: "OpenAI temperature, lower is deterministic",
				Value: 0.0,
			},
			&cli.Int64Flag{
				Name:  maxTokens,
				Usage: "OpenAI max number of tokens to generate",
				Value: 1000,
			},
			&cli.StringSliceFlag{
				Name:  givenEvents,
				Usage: "If provided, only generate docs for the given events",
				Value: nil,
			},
		},
		Action: func(c *cli.Context) error {
			if c.NArg() > 0 {
				return cli.ShowAppHelp(c) // no args, only flags supported
			}

			printAndExitIfHelp(c, true)

			key := c.String(openAIKey)
			if key == "" {
				return fmt.Errorf("you should provide an OpenAI API key")
			}
			temp := c.Float64(temperature)
			if temp < 0.0 || temp > 2.0 {
				return fmt.Errorf("temperature should be between 0.0 and 2.0")
			}
			token := c.Int(maxTokens)
			if token < 0 || token > 4096 {
				return fmt.Errorf("max tokens should be between 0 and 4096")
			}
			events := c.StringSlice(givenEvents)

			runner, err := getGPTDocsRunner(key, temp, token, events)
			if err != nil {
				return err
			}

			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			return runner.Run(ctx)
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func printAndExitIfHelp(c *cli.Context, exit bool) {
	if c.Bool("help") {
		if err := cli.ShowAppHelp(c); err != nil {
			log.Fatal(err)
		}
		if exit {
			os.Exit(0)
		}
	}
}

func getGPTDocsRunner(k string, t float64, m int, e []string) (
	*cmd.GPTDocsRunner, error,
) {
	return &cmd.GPTDocsRunner{
		OpenAIKey:         k,
		OpenAITemperature: t,
		OpenAIMaxTokens:   m,
		GivenEvents:       e,
	}, nil
}

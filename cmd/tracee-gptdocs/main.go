package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/aquasecurity/tracee/pkg/cmd/urfave"
	"github.com/urfave/cli/v2"
)

const (
	openAIKey   = "openaikey"
	temperature = "temperature"
	maxTokens   = "maxtokens"
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
				Usage: "OpenAI sampling temperature (lower is more deterministic)",
				Value: 0.0,
			},
			&cli.Int64Flag{
				Name:  maxTokens,
				Usage: "OpenAI max number of tokens to generate",
				Value: 1000,
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

			runner, err := urfave.GetGPTDocsRunner(c, key, temp, token)
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
		cli.ShowAppHelp(c)
		if exit {
			os.Exit(0)
		}
	}
}

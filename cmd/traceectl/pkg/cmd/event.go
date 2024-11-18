package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/client"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/printer"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/config"
)

type EnableEvent struct {
	Config  config.Config
	Printer *cobra.Command
	Server  *client.Server
}

func (e EnableEvent) Run(args []string) error {
	if err := e.Server.Connect(); err != nil {
		return fmt.Errorf("error running enabling event: %s", err)
	}
	defer e.Server.Close()
	if _, err := e.Server.EnableEvent(context.Background(), &pb.EnableEventRequest{Name: args[0]}); err != nil {
		return fmt.Errorf("error enabling event: %s", err)
	}
	e.Printer.Printf("Enabled event: %s\n", args[0])
	return nil
}

type DisableEvent struct {
	Config  config.Config
	Printer *cobra.Command
	Server  *client.Server
}

func (e DisableEvent) Run(args []string) error {
	if err := e.Server.Connect(); err != nil {
		return fmt.Errorf("error running disable event: %s", err)
	}
	defer e.Server.Close()
	if _, err := e.Server.DisableEvent(context.Background(), &pb.DisableEventRequest{Name: args[0]}); err != nil {
		return fmt.Errorf("error disabling event: %s", err)
	}
	e.Printer.Printf("Disabled event: %s\n", args[0])
	return nil
}

type DescribeEvent struct {
	Config  config.Config
	Printer printer.DescribeEventPrinter
	Server  *client.Server
}

func (e DescribeEvent) Run(args []string) error {
	if err := e.Server.Connect(); err != nil {
		return fmt.Errorf("error running describe events: %s", err)
	}
	defer e.Server.Close()

	e.Printer.Preamble()

	response, err := e.Server.GetEventDefinitions(context.Background(), &pb.GetEventDefinitionsRequest{EventNames: args})
	if err != nil {
		return err
	}

	for _, event := range response.Definitions {
		e.Printer.Print(event)
	}

	e.Printer.Epilogue()
	e.Printer.Close()

	return nil
}

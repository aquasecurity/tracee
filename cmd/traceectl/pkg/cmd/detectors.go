package cmd

import (
	"context"
	"errors"
	"fmt"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/client"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/printer"
)

type ListDetectors struct {
	Printer printer.ListDetectorsPrinter
	Server  *client.Server
	IDs     []string
}

func (l ListDetectors) Run() error {
	if err := l.Server.Connect(); err != nil {
		return fmt.Errorf("error connecting to tracee: %w", err)
	}
	defer l.Server.Close()

	req := &pb.GetDetectorsCatalogRequest{
		DetectorIds: l.IDs,
	}

	response, err := l.Server.GetDetectorsCatalog(context.Background(), req)
	if err != nil {
		return err
	}

	l.Printer.Preamble()
	for _, entry := range response.GetEntries() {
		l.Printer.Print(entry)
	}
	l.Printer.Epilogue()
	l.Printer.Close()

	return nil
}

type DescribeDetector struct {
	Printer printer.DescribeDetectorPrinter
	Server  *client.Server
	Name    string
	ID      string
}

func (d DescribeDetector) Run(args []string) error {
	name := d.Name
	if name == "" && len(args) > 0 {
		name = args[0]
	}

	if name == "" && d.ID == "" {
		return errors.New("event name or detector id is required")
	}

	if err := d.Server.Connect(); err != nil {
		return fmt.Errorf("error connecting to tracee: %w", err)
	}
	defer d.Server.Close()

	req := &pb.GetDetectorsCatalogRequest{}
	if name != "" {
		req.EventNames = []string{name}
	}
	if d.ID != "" {
		req.DetectorIds = []string{d.ID}
	}

	response, err := d.Server.GetDetectorsCatalog(context.Background(), req)
	if err != nil {
		return err
	}

	if len(response.GetEntries()) == 0 {
		if name != "" {
			return fmt.Errorf("detector not found for event %q", name)
		}
		return fmt.Errorf("detector not found for id %q", d.ID)
	}

	d.Printer.Preamble()
	for _, entry := range response.GetEntries() {
		d.Printer.Print(entry)
	}
	d.Printer.Epilogue()
	d.Printer.Close()

	return nil
}

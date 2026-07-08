package cobra

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/printer"
)

func GetListDetectors(cmdCobra *cobra.Command) (cmd.ListDetectors, error) {
	var list cmd.ListDetectors

	serverValue, err := cmdCobra.Flags().GetString(flags.ServerFlag)
	if err != nil {
		return list, fmt.Errorf("failed to read server flag: %w", err)
	}
	server, err := flags.PrepareServer(serverValue)
	if err != nil {
		return list, err
	}

	formatValue, err := cmdCobra.Flags().GetString(flags.FormatFlag)
	if err != nil {
		return list, fmt.Errorf("failed to read format flag: %w", err)
	}
	format, err := flags.PrepareFormat(formatValue)
	if err != nil {
		return list, err
	}

	p, err := printer.NewListDetectorsPrinter(cmdCobra, format)
	if err != nil {
		return list, err
	}

	ids, err := cmdCobra.Flags().GetStringSlice("id")
	if err != nil {
		return list, fmt.Errorf("failed to read id flag: %w", err)
	}

	list.Printer = p
	list.Server = server
	list.IDs = ids
	return list, nil
}

func GetDescribeDetector(cmdCobra *cobra.Command) (cmd.DescribeDetector, error) {
	var describe cmd.DescribeDetector

	serverValue, err := cmdCobra.Flags().GetString(flags.ServerFlag)
	if err != nil {
		return describe, fmt.Errorf("failed to read server flag: %w", err)
	}
	server, err := flags.PrepareServer(serverValue)
	if err != nil {
		return describe, err
	}

	formatValue, err := cmdCobra.Flags().GetString(flags.FormatFlag)
	if err != nil {
		return describe, fmt.Errorf("failed to read format flag: %w", err)
	}
	format, err := flags.PrepareFormat(formatValue)
	if err != nil {
		return describe, err
	}

	p, err := printer.NewDescribeDetectorPrinter(cmdCobra, format)
	if err != nil {
		return describe, err
	}

	name, err := cmdCobra.Flags().GetString("name")
	if err != nil {
		return describe, fmt.Errorf("failed to read name flag: %w", err)
	}

	id, err := cmdCobra.Flags().GetString("id")
	if err != nil {
		return describe, fmt.Errorf("failed to read id flag: %w", err)
	}

	describe.Printer = p
	describe.Server = server
	describe.Name = name
	describe.ID = id
	return describe, nil
}

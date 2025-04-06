package cobra

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/printer"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/config"
)

func GetDescribeEvent(cmdCobra *cobra.Command) (cmd.DescribeEvent, error) {
	var event cmd.DescribeEvent
	// get flags through cobra and not viper
	// viper will takes flags from the highest available source (so flags before config file)
	// that means when we want to use config file in the future we will need to modify the code

	serverValue, err := cmdCobra.Flags().GetString(flags.ServerFlag)
	if err != nil {
		return event, fmt.Errorf("failed to read server flag: %w", err)
	}
	server, err := flags.PrepareServer(serverValue)
	if err != nil {
		return event, err
	}

	outputValue, err := cmdCobra.Flags().GetString(flags.OutputFlag)
	if err != nil {
		return event, fmt.Errorf("failed to read output flag: %w", err)
	}
	output, err := flags.PrepareOutput(cmdCobra, outputValue)
	if err != nil {
		return event, err
	}

	formatValue, err := cmdCobra.Flags().GetString(flags.FormatFlag)
	if err != nil {
		return event, fmt.Errorf("failed to read format flag: %w", err)
	}
	format, err := flags.PrepareFormat(formatValue)
	if err != nil {
		return event, err
	}

	p, err := printer.NewDescribeEventPrinter(cmdCobra, format)
	if err != nil {
		return event, err
	}
	event.Printer = p
	event.Server = server
	event.Config.Printer = config.PrinterConfig{
		Kind:    format,
		OutPath: output.Path,
		OutFile: output.Writer,
	}
	event.Config.Server = config.ServerConfig{
		Protocol: "unix",
		Address:  server.Addr,
	}
	return event, nil
}

func GetEnableEvent(cmdCobra *cobra.Command) (cmd.EnableEvent, error) {
	var event cmd.EnableEvent
	// get flags through cobra and not viper
	// viper will takes flags from the highest available source (so flags before config file)
	// that means when we want to use config file in the future we will need to modify the code

	serverValue, err := cmdCobra.Flags().GetString(flags.ServerFlag)
	if err != nil {
		return event, fmt.Errorf("failed to read server flag: %w", err)
	}
	server, err := flags.PrepareServer(serverValue)
	if err != nil {
		return event, err
	}

	outputValue, err := cmdCobra.Flags().GetString(flags.OutputFlag)
	if err != nil {
		return event, fmt.Errorf("failed to read output flag: %w", err)
	}
	output, err := flags.PrepareOutput(cmdCobra, outputValue)
	if err != nil {
		return event, err
	}

	event.Printer = cmdCobra
	event.Server = server
	event.Config.Printer = config.PrinterConfig{
		Kind:    flags.DefaultFormat,
		OutPath: output.Path,
		OutFile: output.Writer,
	}
	event.Config.Server = config.ServerConfig{
		Protocol: "unix",
		Address:  server.Addr,
	}
	return event, nil
}

func GetDisableEvent(cmdCobra *cobra.Command) (cmd.DisableEvent, error) {
	var event cmd.DisableEvent

	serverValue, err := cmdCobra.Flags().GetString(flags.ServerFlag)
	if err != nil {
		return event, fmt.Errorf("failed to read server flag: %w", err)
	}
	server, err := flags.PrepareServer(serverValue)
	if err != nil {
		return event, err
	}

	outputValue, err := cmdCobra.Flags().GetString(flags.OutputFlag)
	if err != nil {
		return event, fmt.Errorf("failed to read output flag: %w", err)
	}
	output, err := flags.PrepareOutput(cmdCobra, outputValue)
	if err != nil {
		return event, err
	}

	event.Printer = cmdCobra
	event.Server = server
	event.Config.Printer = config.PrinterConfig{
		Kind:    flags.DefaultFormat,
		OutPath: output.Path,
		OutFile: output.Writer,
	}
	event.Config.Server = config.ServerConfig{
		Protocol: "unix",
		Address:  server.Addr,
	}
	return event, nil
}

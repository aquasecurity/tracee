package cobra

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/printer"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/config"
)

func GetDescribeEvent(cmdCobra *cobra.Command) (cmd.DescribeEvent, error) {
	var event cmd.DescribeEvent

	server, err := flags.PrepareServer(viper.GetString(flags.ServerFlag))
	if err != nil {
		return event, err
	}
	output, err := flags.PrepareOutput(cmdCobra, viper.GetString(flags.OutputFlag))
	if err != nil {
		return event, err
	}
	format, err := flags.PrepareFormat(viper.GetString(flags.FormatFlag))
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

	server, err := flags.PrepareServer(viper.GetString(flags.ServerFlag))
	if err != nil {
		return event, err
	}
	output, err := flags.PrepareOutput(cmdCobra, viper.GetString(flags.OutputFlag))
	if err != nil {
		return event, err
	}

	event.Server = server
	event.Config.Printer = config.PrinterConfig{
		Kind:    "table",
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

	server, err := flags.PrepareServer(viper.GetString(flags.ServerFlag))
	if err != nil {
		return event, err
	}
	output, err := flags.PrepareOutput(cmdCobra, viper.GetString(flags.OutputFlag))
	if err != nil {
		return event, err
	}

	event.Server = server
	event.Config.Printer = config.PrinterConfig{
		Kind:    "table",
		OutPath: output.Path,
		OutFile: output.Writer,
	}
	event.Config.Server = config.ServerConfig{
		Protocol: "unix",
		Address:  server.Addr,
	}
	return event, nil
}

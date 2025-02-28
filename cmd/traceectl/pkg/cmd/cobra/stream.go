package cobra

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/printer"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/config"
)

func GetStream(cmdCobra *cobra.Command) (cmd.Stream, error) {
	var stream cmd.Stream

	//
	// Prepare Flags
	//

	server, err := flags.PrepareServer(viper.GetString(flags.ServerFlag))
	if err != nil {
		return stream, err
	}

	output, err := flags.PrepareOutput(cmdCobra, viper.GetString(flags.OutputFlag))
	if err != nil {
		return stream, err
	}

	format, err := flags.PrepareFormat(viper.GetString(flags.FormatFlag))
	if err != nil {
		return stream, err
	}

	policies, err := flags.PreparePolicy(viper.GetStringSlice(flags.PolicyFlag))
	if err != nil {
		return stream, err
	}

	//
	//	Create stream runner
	//

	p, err := printer.New(cmdCobra, format)
	if err != nil {
		return stream, err
	}
	stream.Printer = p
	stream.Server = server
	stream.Policies = policies
	stream.Config.Printer = config.PrinterConfig{
		Kind:    format,
		OutPath: output.Path,
		OutFile: output.Writer,
	}
	stream.Config.Server = config.ServerConfig{
		Protocol: "unix",
		Address:  server.Addr,
	}
	return stream, nil
}

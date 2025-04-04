package cobra

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/config"
)

func GetMetrics(cmdCobra *cobra.Command) (cmd.Metrics, error) {
	var metrics cmd.Metrics
	// get flags through cobra and not viper
	// viper will takes flags from the highest available source (so flags before config file)
	// that means when we want to use config file in the future we will need to modify the code

	serverValue, err := cmdCobra.Flags().GetString(flags.ServerFlag)
	if err != nil {
		return metrics, fmt.Errorf("failed to read server flag: %w", err)
	}
	server, err := flags.PrepareServer(serverValue)
	if err != nil {
		return metrics, err
	}

	metrics.Server = server
	metrics.Printer = cmdCobra
	metrics.Config.Printer = config.PrinterConfig{
		Kind:    flags.DefaultFormat,
		OutPath: flags.DefaultOutput,
		OutFile: cmdCobra.OutOrStdout(),
	}
	metrics.Config.Server = config.ServerConfig{
		Protocol: "unix",
		Address:  server.Addr,
	}

	return metrics, nil
}

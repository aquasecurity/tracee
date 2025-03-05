package cobra

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/config"
)

func GetMetrics(cmdCobra *cobra.Command) (cmd.Metrics, error) {
	var metrics cmd.Metrics

	server, err := flags.PrepareServer(viper.GetString(flags.ServerFlag))
	if err != nil {
		return metrics, err
	}

	metrics.Server = server
	metrics.Printer = cmdCobra
	metrics.Config.Printer = config.PrinterConfig{
		Kind:    "table",
		OutPath: viper.GetString(flags.OutputFlag),
		OutFile: cmdCobra.OutOrStdout(),
	}
	metrics.Config.Server = config.ServerConfig{
		Protocol: "unix",
		Address:  server.Addr,
	}

	return metrics, nil
}

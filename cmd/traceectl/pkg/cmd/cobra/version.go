package cobra

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/config"
)

func GetVersion(cmdCobra *cobra.Command) (cmd.Version, error) {
	var version cmd.Version

	server, err := flags.PrepareServer(viper.GetString(flags.ServerFlag))
	if err != nil {
		return version, err
	}

	version.Server = server
	version.Printer = cmdCobra
	version.Config.Printer = config.PrinterConfig{
		Kind:    "table",
		OutPath: viper.GetString(flags.OutputFlag),
		OutFile: cmdCobra.OutOrStdout(),
	}
	version.Config.Server = config.ServerConfig{
		Protocol: "unix",
		Address:  server.Addr,
	}
	return version, nil
}

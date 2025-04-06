package cobra

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/config"
)

func GetVersion(cmdCobra *cobra.Command) (cmd.Version, error) {
	var version cmd.Version
	// get flags through cobra and not viper
	// viper will takes flags from the highest available source (so flags before config file)
	// that means when we want to use config file in the future we will need to modify the code

	serverValue, err := cmdCobra.Flags().GetString(flags.ServerFlag)
	if err != nil {
		return version, fmt.Errorf("failed to read server flag: %w", err)
	}
	server, err := flags.PrepareServer(serverValue)
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

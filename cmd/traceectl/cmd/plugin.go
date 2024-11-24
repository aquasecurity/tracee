package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var pluginCmd = &cobra.Command{
	Use:   "plugin",
	Short: "Plugin management for traceectl",
	Long: `Plugin Management:
  	- traceectl plugin install --name <plugin_name> --repo <repository_url>
  	- traceectl plugin list
  	- traceectl plugin uninstall <plugin_name>
`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("plugin called")
	},
}

func init() {
	pluginCmd.AddCommand(pluginInstallCmd)
	pluginCmd.AddCommand(pluginListCmd)
	pluginCmd.AddCommand(pluginUninstallCmd)
}

var pluginInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install a plugin from a remote repository",
	Long: `Install a plugin from a remote repository:	
  	- traceectl plugin install --name <plugin_name> --repo <repository_url>
`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("install called")
	},
}

var pluginListCmd = &cobra.Command{
	Use:   "list",
	Short: "List installed plugins",
	Long:  `List all installed plugins.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("list called")
	},
}

var pluginUninstallCmd = &cobra.Command{
	Use:   "uninstall <plugin_name>",
	Short: "Uninstall a plugin",
	Long:  `Uninstalls a plugin by its name.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("uninstall called")
	},
}

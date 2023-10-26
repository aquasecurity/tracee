package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/aquasecurity/tracee/pkg/errfmt"
)

func init() {
	rootCmd.AddCommand(manCmd)

	// add subcommands to manCmd
	manCmd.AddCommand(
		cacheCmd,
		capabilitiesCmd,
		captureCmd,
		configCmd,
		containersCmd,
		eventsCmd,
		logCmd,
		outputCmd,
		regoCmd,
		scopeCmd,
	)
}

var manCmd = &cobra.Command{
	Use:     "man",
	Aliases: []string{"m"},
	Short:   "Open man page for a specified flag name",
	Run: func(cmd *cobra.Command, args []string) {
		// if here, no valid subcommand was provided
		if err := cmd.Help(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			os.Exit(1)
		}
	},
	DisableFlagsInUseLine: true,
}

var cacheCmd = &cobra.Command{
	Use:     "cache",
	Aliases: []string{"a"},
	Short:   "cache flag help",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runManForFlag("cache")
	},
}

var capabilitiesCmd = &cobra.Command{
	Use:     "capabilities",
	Aliases: []string{"C"},
	Short:   "capabilities flag help",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runManForFlag("capabilities")
	},
}

var captureCmd = &cobra.Command{
	Use:     "capture",
	Aliases: []string{"c"},
	Short:   "capture flag help",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runManForFlag("capture")
	},
}

var configCmd = &cobra.Command{
	Use:     "config",
	Aliases: []string{},
	Short:   "config flag help",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runManForFlag("config")
	},
}

var containersCmd = &cobra.Command{
	Use:     "cri",
	Aliases: []string{},
	Short:   "containers flag help",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runManForFlag("cri")
	},
}

var eventsCmd = &cobra.Command{
	Use:     "events",
	Aliases: []string{"e"},
	Short:   "events flag help",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runManForFlag("events")
	},
}

var logCmd = &cobra.Command{
	Use:     "log",
	Aliases: []string{"l"},
	Short:   "log flag help",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runManForFlag("log")
	},
}

var outputCmd = &cobra.Command{
	Use:     "output",
	Aliases: []string{"o"},
	Short:   "output flag help",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runManForFlag("output")
	},
}

var regoCmd = &cobra.Command{
	Use:     "rego",
	Aliases: []string{},
	Short:   "rego flag help",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runManForFlag("rego")
	},
}

var scopeCmd = &cobra.Command{
	Use:     "scope",
	Aliases: []string{"s"},
	Short:   "scope flag help",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runManForFlag("scope")
	},
}

// runManForFlag runs man for the specified flag name
func runManForFlag(flagName string) error {
	const manHelpPath = "./docs/man"
	manFlagFile := fmt.Sprintf("%s/%s.1", manHelpPath, flagName)
	manFlagFileAbs, err := filepath.Abs(manFlagFile)
	if err != nil {
		return errfmt.WrapError(err)
	}

	// check if the file exists
	if _, err := os.Stat(manFlagFileAbs); os.IsNotExist(err) {
		return errfmt.WrapError(err)
	}

	// execute man
	manPath := "/usr/bin/man"
	cmd := exec.Command(manPath, manFlagFileAbs)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	return errfmt.WrapError(err)
}

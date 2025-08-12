package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/aquasecurity/tracee"
	"github.com/aquasecurity/tracee/pkg/errfmt"
)

func init() {
	rootCmd.AddCommand(manCmd)

	// add subcommands to manCmd
	manCmd.AddCommand(
		capabilitiesCmd,
		captureCmd,
		configCmd,
		containersCmd,
		eventsCmd,
		logCmd,
		outputCmd,
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
	Use:     "containers",
	Aliases: []string{},
	Short:   "containers flag help",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runManForFlag("containers")
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
	// Read the embedded manual page
	manFileName := fmt.Sprintf("docs/man/%s.1", flagName)
	manContent, err := tracee.ManPagesBundle.ReadFile(manFileName)
	if err != nil {
		return errfmt.Errorf("manual page not found for %s: %v", flagName, err)
	}

	// Create a temporary file with the manual content
	tmpFile, err := os.CreateTemp("", fmt.Sprintf("tracee-man-%s-*.1", flagName))
	if err != nil {
		return errfmt.WrapError(err)
	}
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
	}()

	// Write the embedded content to the temporary file
	if _, err := tmpFile.Write(manContent); err != nil {
		return errfmt.WrapError(err)
	}

	// Close the file so man can read it
	if err := tmpFile.Close(); err != nil {
		return errfmt.WrapError(err)
	}

	// Execute man on the temporary file
	manPath := "/usr/bin/man"
	cmd := exec.Command(manPath, tmpFile.Name())
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	return errfmt.WrapError(err)
}

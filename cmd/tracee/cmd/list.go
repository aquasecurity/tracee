package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/aquasecurity/tracee/pkg/cmd"
	"github.com/aquasecurity/tracee/pkg/cmd/initialize/sigs"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/signatures/signature"
)

func init() {
	rootCmd.AddCommand(listCmd)
	listCmd.Flags().BoolP(
		"wide",
		"w",
		false,
		"no wrapping of output lines",
	)
	listCmd.Flags().StringArray(
		"signatures-dir",
		[]string{},
		"Directories where to search for signatures in Go plugin (.so) format",
	)
}

var listCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"l"},
	Short:   "List traceable events",
	Long:    ``,
	Run: func(c *cobra.Command, args []string) {
		// Get signatures to update event list
		sigsDir, err := c.Flags().GetStringArray("signatures-dir")
		if err != nil {
			logger.Fatalw("Failed to get signatures-dir flag", "err", err)
			os.Exit(1)
		}

		signatures, _, err := signature.Find(sigsDir, nil)
		if err != nil {
			logger.Fatalw("Failed to find signatures", "err", err)
			os.Exit(1)
		}

		sigs.CreateEventsFromSignatures(events.StartSignatureID, signatures)

		includeSigs := true
		wideOutput := c.Flags().Lookup("wide").Value.String() == "true"
		cmd.PrintEventList(includeSigs, wideOutput) // list events
	},
	DisableFlagsInUseLine: true,
}

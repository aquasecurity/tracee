package cmd

import (
	"os"

	"github.com/open-policy-agent/opa/compile"
	"github.com/spf13/cobra"

	"github.com/aquasecurity/tracee/pkg/cmd"
	"github.com/aquasecurity/tracee/pkg/cmd/initialize"
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
		"Directories where to search for signatures in OPA (.rego) and Go plugin (.so) formats",
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

		sigs, _, err := signature.Find(
			compile.TargetRego,
			false,
			sigsDir,
			nil,
			false,
		)
		if err != nil {
			logger.Fatalw("Failed to find signatures", "err", err)
			os.Exit(1)
		}

		initialize.CreateEventsFromSignatures(events.StartSignatureID, sigs)

		includeSigs := true
		wideOutput := c.Flags().Lookup("wide").Value.String() == "true"
		cmd.PrintEventList(includeSigs, wideOutput) // list events
	},
	DisableFlagsInUseLine: true,
}

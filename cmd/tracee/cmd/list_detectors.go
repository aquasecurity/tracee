package cmd

import (
	"github.com/spf13/cobra"

	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/cmd"
	"github.com/aquasecurity/tracee/pkg/detectors"
)

func init() {
	listDetectorsCmd.Flags().BoolP(
		"json",
		"j",
		false,
		"Output in JSON format",
	)
}

var listDetectorsCmd = &cobra.Command{
	Use:   "detectors [paths...]",
	Short: "List available detectors and shared lists",
	Long: `List all available detectors and shared lists from built-in and YAML sources.

Detectors analyze events and produce threat detections or derived events.
Shared lists are reusable value sets referenced by YAML detectors in CEL expressions.

Arguments:
  [paths...]  Directories or files to search for YAML detectors and lists.
              If not specified, uses default paths (/etc/tracee/detectors).

Examples:
  tracee list detectors                       # All detectors and lists from default paths
  tracee list detectors ./my-detectors        # Detectors and lists from custom directory
  tracee list detectors ./dir1 ./dir2         # Detectors and lists from multiple directories
  tracee list detectors --json                # JSON output for scripting`,
	Run: func(c *cobra.Command, args []string) {
		logger.Init(logger.NewDefaultLoggingConfig())

		jsonOutput, _ := c.Flags().GetBool("json")

		// Use positional arguments as paths, or nil for defaults
		var searchDirs []string
		if len(args) > 0 {
			searchDirs = args
		}

		// Collect all detectors and shared lists
		allDetectors := detectors.CollectAllDetectors(searchDirs)
		allLists := detectors.CollectAllLists(searchDirs)

		// Print detector and list info
		if err := cmd.PrintDetectorList(allDetectors, allLists, jsonOutput); err != nil {
			logger.Fatalw("Failed to print detector list", "err", err)
		}
	},
	DisableFlagsInUseLine: true,
}

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
	Short: "List available detectors",
	Long: `List all available detectors from built-in and YAML sources.

Detectors analyze events and produce threat detections or derived events.

Arguments:
  [paths...]  Directories or files to search for YAML detectors.
              If not specified, uses default paths (/etc/tracee/detectors).

Examples:
  tracee list detectors                       # All detectors from default paths
  tracee list detectors ./my-detectors        # Detectors from custom directory
  tracee list detectors ./dir1 ./dir2         # Detectors from multiple directories
  tracee list detectors ./detector.yaml       # Single detector file
  tracee list detectors --json                # JSON output for scripting`,
	Run: func(c *cobra.Command, args []string) {
		logger.Init(logger.NewDefaultLoggingConfig())

		jsonOutput, _ := c.Flags().GetBool("json")

		// Use positional arguments as paths, or nil for defaults
		var searchDirs []string
		if len(args) > 0 {
			searchDirs = args
		}

		// Collect all detectors
		allDetectors := detectors.CollectAllDetectors(searchDirs)

		// Print detector list
		if err := cmd.PrintDetectorList(allDetectors, jsonOutput); err != nil {
			logger.Fatalw("Failed to print detector list", "err", err)
		}
	},
	DisableFlagsInUseLine: true,
}

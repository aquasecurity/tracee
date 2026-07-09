package cmd

import (
	"github.com/spf13/cobra"

	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/cmd"
	"github.com/aquasecurity/tracee/pkg/detectors"
	"github.com/aquasecurity/tracee/pkg/events"
)

func init() {
	listDepsCmd.Flags().StringP(
		"format",
		"f",
		"tree",
		"Output format: tree, mermaid, or json",
	)
}

var listDepsCmd = &cobra.Command{
	Use:   "deps <event> [event...]",
	Short: "Show an event's dependency graph",
	Long: `Show the dependency graph of one or more events: the base events each one needs,
annotated with probe and kernel-symbol dependencies. Detector and derived events expand into
the base events they consume, so this also reveals which raw events a detector chain rests on.

Formats:
  tree     (default) ASCII indented tree
  mermaid  a fenced mermaid flowchart, ready to paste into docs
  json     structured output for scripting

Examples:
  tracee list deps net_packet_icmp
  tracee list deps sched_process_exec --format mermaid
  tracee list deps security_file_open --format json`,
	Args: cobra.MinimumNArgs(1),
	Run: func(c *cobra.Command, args []string) {
		logger.Init(logger.NewDefaultLoggingConfig())

		// Register detector events so detector chains resolve too.
		allDetectors := detectors.CollectAllDetectors(nil)
		if _, err := detectors.CreateEventsFromDetectors(events.StartDetectorID, allDetectors); err != nil {
			logger.Fatalw("Failed to register detector events", "err", err)
		}

		format, _ := c.Flags().GetString("format")
		if err := cmd.PrintEventDeps(args, format); err != nil {
			logger.Fatalw("Failed to print event dependencies", "err", err)
		}
	},
	DisableFlagsInUseLine: true,
}

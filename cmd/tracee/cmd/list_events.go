package cmd

import (
	"github.com/spf13/cobra"

	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/cmd"
	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/detectors"
	"github.com/aquasecurity/tracee/pkg/events"
)

func init() {
	// Output flags only - filters are positional arguments
	listEventsCmd.Flags().BoolP(
		"json",
		"j",
		false,
		"Output in JSON format",
	)
}

var listEventsCmd = &cobra.Command{
	Use:   "events [filters...]",
	Short: "List traceable events with optional filtering",
	Long: `List all events that can be traced, with optional filtering.

Uses the same filter syntax as 'tracee --events' for consistency.

Filter Patterns:
  eventname                    Exact event name match
  open*                        Wildcard pattern (prefix, suffix, or contains)
  tag=fs                       Filter by tag/set
  tag=fs,network               Filter by tag (OR within comma-separated values)
  type=syscall                 Filter by event type (syscall, detector, network)
  threat.severity=critical     Filter by threat severity
  threat.mitre.technique=T1055 Filter by MITRE ATT&CK technique ID
  threat.mitre.tactic=Execution Filter by MITRE ATT&CK tactic name

Multiple filters are combined with AND logic.

Examples:
  tracee list events                              # All events
  tracee list events open                         # Event named 'open'
  tracee list events 'open*'                      # Events starting with 'open'
  tracee list events tag=fs                       # Events with 'fs' tag
  tracee list events tag=fs,network               # Events with 'fs' OR 'network' tag
  tracee list events tag=fs tag=proc              # Events with 'fs' AND 'proc' tags
  tracee list events type=syscall                 # Syscall events only
  tracee list events type=detector                # Detector events only
  tracee list events threat.severity=critical     # Critical severity events
  tracee list events threat.mitre.technique=T1055 # Events detecting T1055
  tracee list events threat.mitre.tactic=Execution # Events in Execution tactic
  tracee list events tag=fs threat.severity=high  # Combined filters (AND)
  tracee list events --json                       # JSON output for scripting`,
	Run: func(c *cobra.Command, args []string) {
		logger.Init(logger.NewDefaultLoggingConfig())

		// Collect and register detector events so they appear in the list
		allDetectors := detectors.CollectAllDetectors(nil)
		_, err := detectors.CreateEventsFromDetectors(events.StartDetectorID, allDetectors)
		if err != nil {
			logger.Fatalw("Failed to register detector events", "err", err)
		}

		// Parse positional arguments as filters
		filterConfig := flags.ParseEventFilters(args)

		jsonOutput, _ := c.Flags().GetBool("json")

		// Print filtered event list
		if err := cmd.PrintEventList(filterConfig, jsonOutput); err != nil {
			logger.Fatalw("Failed to print event list", "err", err)
		}
	},
	DisableFlagsInUseLine: true,
}

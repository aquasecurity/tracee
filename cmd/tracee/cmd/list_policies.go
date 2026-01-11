package cmd

import (
	"github.com/spf13/cobra"

	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/cmd"
	"github.com/aquasecurity/tracee/pkg/detectors"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/policy/v1beta1"
)

const defaultPolicyDir = "/etc/tracee/policies"

func init() {
	listPoliciesCmd.Flags().BoolP(
		"json",
		"j",
		false,
		"Output in JSON format",
	)
}

var listPoliciesCmd = &cobra.Command{
	Use:   "policies [paths...]",
	Short: "List policies from a directory",
	Long: `List all policies from the specified directories or files.

Policies define what events to trace and how to filter them.

Arguments:
  [paths...]  Directories or files to search for policies.
              If not specified, uses default path (/etc/tracee/policies).

Examples:
  tracee list policies                    # Policies from default path
  tracee list policies ./my-policies      # Policies from custom directory
  tracee list policies ./dir1 ./dir2      # Policies from multiple directories
  tracee list policies ./policy.yaml      # Single policy file
  tracee list policies --json             # JSON output for scripting`,
	Run: func(c *cobra.Command, args []string) {
		logger.Init(logger.NewDefaultLoggingConfig())

		jsonOutput, _ := c.Flags().GetBool("json")

		// Register detector-produced events before loading policies so policy validation
		// can resolve detector event names (e.g., "anti_debugging") against events.Core.
		allDetectors := detectors.CollectAllDetectors(nil)
		if _, err := detectors.CreateEventsFromDetectors(events.StartDetectorID, allDetectors); err != nil {
			logger.Fatalw("Failed to register detector events", "err", err)
		}

		// Use positional arguments as paths, or default
		policyPaths := args
		if len(policyPaths) == 0 {
			policyPaths = []string{defaultPolicyDir}
		}

		// Load policies from paths
		policies, err := v1beta1.PoliciesFromPaths(policyPaths)
		if err != nil {
			// Don't fail if default directory doesn't exist
			if !(len(policyPaths) == 1 && policyPaths[0] == defaultPolicyDir) {
				logger.Fatalw("Failed to load policies", "err", err)
			}
			logger.Debugw("Default policy directory not found", "path", defaultPolicyDir)
			policies = nil
		}

		// Print policy list
		if err := cmd.PrintPolicyList(policies, jsonOutput); err != nil {
			logger.Fatalw("Failed to print policy list", "err", err)
		}
	},
	DisableFlagsInUseLine: true,
}

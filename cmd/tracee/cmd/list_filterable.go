package cmd

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/cmd"
	"github.com/aquasecurity/tracee/pkg/detectors"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/policy"
)

// pathExists reports whether p resolves to an existing file or directory.
func pathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// looksLikePolicyPath reports whether an argument is clearly a policy file/dir reference (a path
// separator or a policy extension) even if it does not exist - so a typo'd path is reported as a
// missing policy rather than an "unknown event".
func looksLikePolicyPath(a string) bool {
	if strings.ContainsAny(a, `/\`) {
		return true
	}
	switch strings.ToLower(filepath.Ext(a)) {
	case ".yaml", ".yml", ".json":
		return true
	}
	return false
}

func init() {
	listFilterableCmd.Flags().BoolP("json", "j", false, "Output in JSON format")
	listFilterableCmd.Flags().StringSlice(
		"policy",
		nil,
		"Analyze policy file(s) or director(ies) instead of listing an event's fields",
	)
	listFilterableCmd.Flags().String(
		"config",
		"",
		"Policy analysis: a Tracee config file whose DNS-cache and detector settings affect the report "+
			"(process store / captures add only internal control-plane events, so they do not)",
	)
}

var listFilterableCmd = &cobra.Command{
	Use:   "filterable [event...]",
	Short: "Show which event fields filter in the kernel vs user space",
	Long: `Show where each of an event's filters is enforced.

Kernel filters drop non-matching instances BEFORE the event is submitted (the cheapest
filtering); user-space filters run AFTER submission. Scope filters (comm, uid, ...) and the
pathname data filter are kernel-enforced; other data fields and return-value filters run in
user space.

Two modes:

  Static (events as arguments) - classify each event's fields:
      tracee list filterable security_file_open
      tracee list filterable sched_process_exec security_file_open --json

  Policy-aware - load real policies and, per selected event, report whether in-kernel filtering
  is effective, defeated by a broad (unfiltered) selector, or lost to overflow (an event selected
  by more than 64 rules). A positional policy file/directory is detected automatically; --policy
  works too:
      tracee list filterable ./policies
      tracee list filterable ./my-policy.yaml
      tracee list filterable --policy ./p1.yaml --policy ./p2.yaml --json

  Pass --config <tracee-config> to fold in the configured detectors' declared base scope filters and
  reflect the DNS cache (which force-collects net_packet_dns). Process-store and capture settings add
  only internal control-plane events (a separate perf buffer), so they do not change the report.
  Without --config the policies are analyzed on their own:
      tracee list filterable ./policies --config /etc/tracee/tracee.yaml`,
	Run: func(c *cobra.Command, args []string) {
		logger.Init(logger.NewDefaultLoggingConfig())

		jsonOutput, _ := c.Flags().GetBool("json")
		policyPaths, _ := c.Flags().GetStringSlice("policy")
		configPath, _ := c.Flags().GetString("config")

		// A --config file defines the real scenario: its ManagerConfig settings drive which events are
		// force-collected, and its detectors' base scopes are folded in. Without it, analyze the policies
		// alone with a minimal config.
		var managerCfg policy.ManagerConfig
		var detectorDirs []string
		foldDetectors := false
		if configPath != "" {
			var err error
			managerCfg, detectorDirs, err = cmd.LoadScenarioConfig(configPath)
			if err != nil {
				logger.Fatalw("Failed to load config", "err", err)
			}
			foldDetectors = true
		}

		// Register detector events so their names resolve (static mode) and their outputs can be selected
		// by policies. Use the config's detector dirs when given.
		allDetectors := detectors.CollectAllDetectors(detectorDirs)
		if _, err := detectors.CreateEventsFromDetectors(events.StartDetectorID, allDetectors); err != nil {
			logger.Fatalw("Failed to register detector events", "err", err)
		}

		// Positional args may be event names OR policy file/dir paths. Route each by whether it
		// resolves to a path, so `list filterable ./my-policy.yaml` works without a flag.
		var eventNames []string
		for _, a := range args {
			switch {
			case pathExists(a):
				policyPaths = append(policyPaths, a)
			case looksLikePolicyPath(a):
				logger.Fatalw("no such policy file or directory", "path", a)
			default:
				eventNames = append(eventNames, a)
			}
		}

		if len(policyPaths) > 0 {
			if len(eventNames) > 0 {
				logger.Fatalw("pass either event names or policy paths, not both", "events", eventNames)
			}
			var detectorList []detection.EventDetector
			if foldDetectors {
				detectorList = allDetectors
			}
			if err := cmd.PrintPolicyFilterability(policyPaths, managerCfg, detectorList, jsonOutput); err != nil {
				logger.Fatalw("Failed to analyze policies", "err", err)
			}
			return
		}

		if len(eventNames) == 0 {
			logger.Fatalw("provide event name(s), a policy file/directory, or --policy <path>")
		}
		if err := cmd.PrintFilterableFields(eventNames, jsonOutput); err != nil {
			logger.Fatalw("Failed to print filterable fields", "err", err)
		}
	},
	DisableFlagsInUseLine: true,
}

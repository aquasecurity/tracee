package cmd

import (
	"context"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aquasecurity/tracee/common/logger"
	cmdcmd "github.com/aquasecurity/tracee/pkg/cmd"
	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/detectors"
	"github.com/aquasecurity/tracee/pkg/events"
)

func init() {
	rootCmd.AddCommand(replayCmd)

	// Output flag
	replayCmd.Flags().StringArrayP(
		"output",
		"o",
		[]string{"json:stdout"},
		"[json|table|webhook...]\t\tControl how and where output is printed",
	)

	// Detectors flag
	replayCmd.Flags().StringArray(
		flags.DetectorsFlag,
		[]string{},
		"[path...]\t\t\t\tConfigure YAML detector search directories or files",
	)

	// Logging flag
	replayCmd.Flags().StringArrayP(
		flags.LoggingFlag,
		flags.LoggingFlagShort,
		[]string{flags.DefaultLogLevelFlag},
		"[debug|info|warn...]\t\tLogger options",
	)
}

var replayCmd = &cobra.Command{
	Use:   "replay <file>",
	Short: "Replay past events from a file and process them with detectors",
	Long: `Replay allows you to replay past events from a file and process them with detectors.

This is useful for analyzing historical event data, testing detector configurations, and debugging detector behavior.

Only low-level events should be replayed. Detector events (high-level events)
will be automatically filtered out.

The input file should contain events in JSON Lines format, as produced
by tracee with --output json:file.json.

Examples:
  # Basic replay with default settings
  tracee replay events.json

  # Replay with table output
  tracee replay events.json --output table

  # Replay with custom detector directory
  tracee replay events.json --detectors /path/to/detectors

  # Replay with multiple detector directories
  tracee replay events.json --detectors /path/to/detectors --detectors /another/path

  # Replay with debug logging
  tracee replay events.json --log debug

  # Complete workflow: capture then replay
  tracee --events execve,openat --output json:events.json
  tracee replay events.json --output table --detectors /etc/tracee/detectors`,
	Args: cobra.ExactArgs(1), // Require exactly one positional argument
	PreRun: func(cmd *cobra.Command, args []string) {
		err := viper.BindPFlag("output", cmd.Flags().Lookup("output"))
		if err != nil {
			logger.Fatalw("Error binding viper flag", "flag", "output", "error", err)
		}
		err = viper.BindPFlag(flags.DetectorsFlag, cmd.Flags().Lookup(flags.DetectorsFlag))
		if err != nil {
			logger.Fatalw("Error binding viper flag", "flag", flags.DetectorsFlag, "error", err)
		}
		err = viper.BindPFlag(flags.LoggingFlag, cmd.Flags().Lookup(flags.LoggingFlag))
		if err != nil {
			logger.Fatalw("Error binding viper flag", "flag", flags.LoggingFlag, "error", err)
		}
	},
	Run:                   replayCommand,
	DisableFlagsInUseLine: true,
}

func replayCommand(cmd *cobra.Command, args []string) {
	filePath := args[0] // Positional argument

	// Initialize logger
	logFlags := viper.GetStringSlice(flags.LoggingFlag)
	loggerConfig, err := flags.PrepareLogger(logFlags)
	if err != nil {
		logger.Fatalw("Failed to prepare logger", "error", err)
	}
	logger.Init(loggerConfig.GetLoggingConfig())

	// Get YAML detector directories
	var yamlDetectorDirs []string
	if viper.IsSet(flags.DetectorsFlag) {
		detectorsFlags, err := flags.GetFlagsFromViper(flags.DetectorsFlag)
		if err != nil {
			logger.Fatalw("Failed to get detectors flags", "error", err)
		}
		detectorsConfig, err := flags.PrepareDetectors(detectorsFlags)
		if err != nil {
			logger.Fatalw("Failed to prepare detectors config", "error", err)
		}
		yamlDetectorDirs = detectorsConfig.Paths
	}

	// Pre-register detector events in events.Core before policy initialization
	// This must happen before the runner creates the policy manager
	allDetectors := detectors.CollectAllDetectors(yamlDetectorDirs)
	if len(allDetectors) == 0 {
		logger.Fatalw("No detectors available")
	}

	_, err = detectors.CreateEventsFromDetectors(events.StartDetectorID, allDetectors)
	if err != nil {
		logger.Fatalw("Failed to create detector events", "error", err)
	}

	// Prepare output configuration
	outputFlags, err := flags.GetFlagsFromViper(flags.OutputFlag)
	if err != nil {
		logger.Fatalw("Failed to get output flags", "error", err)
	}

	output, err := flags.PrepareOutput(outputFlags, config.ContainerModeDisabled)
	if err != nil {
		logger.Fatalw("Failed to prepare output", "error", err)
	}

	// Create config - the runner will handle policy manager creation and event enabling
	cfg := config.Config{
		DetectorConfig: config.DetectorConfig{
			Detectors:      allDetectors,
			YAMLSearchDirs: yamlDetectorDirs,
		},
		Output:          output,
		InitialPolicies: []interface{}{},
	}

	// Create ReplayRunner with file path
	runner := cmdcmd.ReplayRunner{
		TraceeConfig: cfg,
		ReplayPath:   filePath,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	err = runner.Run(ctx)
	if err != nil {
		logger.Fatalw("Replay runner failed", "error", err)
	}
}

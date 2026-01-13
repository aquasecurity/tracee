package cmd

import (
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aquasecurity/tracee/common/digest"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/analyze"
	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/cmd/printer"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/detectors"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/dependencies"
	"github.com/aquasecurity/tracee/pkg/policy"
)

func init() {
	rootCmd.AddCommand(analyzeCmd)

	// flags

	// source
	analyzeCmd.Flags().String(
		"source",
		"",
		"Source file to analyze (required). Currently only JSON is supported.",
	)

	// output
	analyzeCmd.Flags().String(
		"output",
		"json:stdout",
		"Output destination (file, webhook, fluentbit) and format (json, gotemplate=, table) set as <output_path>:<format>",
	)

	// detectors
	analyzeCmd.Flags().StringArray(
		flags.DetectorsFlag,
		[]string{},
		"Detector configuration (e.g., yaml-dir=/path/to/dir)",
	)

	analyzeCmd.Flags().StringArrayP(
		flags.LoggingFlag,
		flags.LoggingFlagShort,
		[]string{flags.DefaultLogLevelFlag},
		"Logger options",
	)
}

var analyzeCmd = &cobra.Command{
	Use:     "analyze [--source file]",
	Aliases: []string{},
	Short:   "Analyze past events with detectors [Experimental]",
	Long: `Analyze allows you to explore detector events with past events.

Tracee can be used to collect events and store it in a file. This file can be used as input to analyze.

eg:
tracee --events ptrace --output=json:events.json
tracee analyze --source events.json`,
	PreRun: func(cmd *cobra.Command, args []string) {
		bindViperFlag(cmd, "source")
		bindViperFlag(cmd, "output")
		bindViperFlag(cmd, flags.LoggingFlag)
		bindViperFlag(cmd, flags.DetectorsFlag)
	},
	Run:                   command,
	DisableFlagsInUseLine: true,
}

func command(cmd *cobra.Command, args []string) {
	logFlags := viper.GetStringSlice(flags.LoggingFlag)

	loggerConfig, err := flags.PrepareLogger(logFlags)
	if err != nil {
		logger.Fatalw("Failed to prepare logger", "error", err)
	}
	logger.Init(loggerConfig.GetLoggingConfig())

	// Set up input
	sourcePath := viper.GetString("source")
	if sourcePath == "" {
		logger.Fatalw("source path cannot be empty")
	}
	sourceFile, err := os.Open(sourcePath)
	if err != nil {
		logger.Fatalw("Failed to get signatures-dir flag", "err", err)
	}

	// Set up printer output (outpath:format)
	outputArg := viper.GetString("output")
	outputParts := strings.SplitN(outputArg, ":", 2)
	if len(outputParts) > 2 || len(outputParts) == 0 {
		logger.Fatalw("Failed to prepare output format (must be of format <format>:<optional_output_path>)")
	}

	outFormat := outputParts[0]
	outPath := ""
	if len(outputParts) > 1 {
		outPath = outputParts[1]
	}

	printerCfg, err := flags.PreparePrinterConfig(outFormat, outPath)
	if err != nil {
		logger.Fatalw("Failed to prepare output configuration", "error", err)
	}
	p, err := printer.New([]config.Destination{printerCfg})
	if err != nil {
		logger.Fatalw("Failed to create printer", "error", err)
	}

	// Get YAML detector directories
	var yamlDetectorDirs []string
	if viper.IsSet(flags.YAMLDirFlag) {
		yamlDetectorDirs = viper.GetStringSlice(flags.YAMLDirFlag)
	} else if viper.IsSet(flags.DetectorsFlag) {
		detectorsFlags, err := flags.GetFlagsFromViper(flags.DetectorsFlag)
		if err != nil {
			logger.Fatalw("Failed to get detectors flags", "error", err)
		}
		detectorsConfig, err := flags.PrepareDetectors(detectorsFlags)
		if err != nil {
			logger.Fatalw("Failed to prepare detectors config", "error", err)
		}
		yamlDetectorDirs = detectorsConfig.YAMLDirs
	}

	// Collect all detectors
	allDetectors := detectors.CollectAllDetectors(yamlDetectorDirs)
	if len(allDetectors) == 0 {
		logger.Fatalw("No detectors available")
	}

	// Create detector events
	_, err = detectors.CreateEventsFromDetectors(events.StartDetectorID, allDetectors)
	if err != nil {
		logger.Fatalw("Failed to create detector events", "error", err)
	}

	// Create dependencies manager for policy manager
	depsManager := dependencies.NewDependenciesManager(
		func(id events.ID) events.DependencyStrategy {
			return events.Core.GetDefinitionByID(id).GetDependencies()
		})

	// Create policy manager with empty policies (all events enabled by default)
	policyMgr, err := policy.NewManager(policy.ManagerConfig{}, depsManager)
	if err != nil {
		logger.Fatalw("Failed to create policy manager", "error", err)
	}

	// Enable all detector events in the policy manager
	for _, detector := range allDetectors {
		def := detector.GetDefinition()
		eventName := def.ProducedEvent.Name
		eventID, found := events.Core.GetDefinitionIDByName(eventName)
		if found {
			policyMgr.EnableEvent(eventID)
		}
	}

	// Extract enrichment options (default to false for analyze mode)
	enrichmentOpts := &detectors.EnrichmentOptions{
		ExecEnv:      false,
		ExecHashMode: digest.CalcHashesNone,
		Container:    false,
	}

	analyze.Analyze(analyze.Config{
		Source:            sourceFile,
		Printer:           p,
		Detectors:         allDetectors,
		PolicyManager:     policyMgr,
		EnrichmentOptions: enrichmentOpts,
	})
}

func bindViperFlag(cmd *cobra.Command, flag string) {
	err := viper.BindPFlag(flag, cmd.Flags().Lookup(flag))
	if err != nil {
		logger.Fatalw("Error binding viper flag", "flag", flag, "error", err)
	}
}

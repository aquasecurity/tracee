package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aquasecurity/tracee/pkg/analyze"
	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/logger"
)

func init() {
	rootCmd.AddCommand(analyzeCmd)

	// flags

	// events
	analyzeCmd.Flags().StringArrayP(
		"events",
		"e",
		[]string{},
		"Define which signature events to load",
	)

	// signatures-dir
	analyzeCmd.Flags().StringArray(
		"signatures-dir",
		[]string{},
		"Directory where to search for signatures in OPA (.rego) and Go plugin (.so) formats",
	)

	// rego
	analyzeCmd.Flags().StringArray(
		"rego",
		[]string{},
		"Control event rego settings",
	)

	analyzeCmd.Flags().StringArrayP(
		"log",
		"l",
		[]string{"info"},
		"Logger options [debug|info|warn...]",
	)
}

var analyzeCmd = &cobra.Command{
	Use:     "analyze input.json",
	Aliases: []string{},
	Args:    cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	Short:   "Analyze past events with signature events [Experimental]",
	Long: `Analyze allow you to explore signature events with past events.

Tracee can be used to collect events and store it in a file. This file can be used as input to analyze.

eg:
tracee --events ptrace --output=json:events.json
tracee analyze --events anti_debugging events.json`,
	PreRun: func(cmd *cobra.Command, args []string) {
		bindViperFlag(cmd, "events")
		bindViperFlag(cmd, "log")
		bindViperFlag(cmd, "rego")
		bindViperFlag(cmd, "signatures-dir")
	},
	Run:                   command,
	DisableFlagsInUseLine: true,
}

func command(cmd *cobra.Command, args []string) {
	logFlags := viper.GetStringSlice("log")

	logCfg, err := flags.PrepareLogger(logFlags, true)
	if err != nil {
		logger.Fatalw("Failed to prepare logger", "error", err)
	}
	logger.Init(logCfg)

	inputFile, err := os.Open(args[0])
	if err != nil {
		logger.Fatalw("Failed to get signatures-dir flag", "err", err)
	}

	// Rego command line flags

	rego, err := flags.PrepareRego(viper.GetStringSlice("rego"))
	if err != nil {
		logger.Fatalw("Failed to parse rego flags", "err", err)
	}

	// Signature directory command line flags

	signatureEvents := viper.GetStringSlice("events")
	// if no event was passed, load all events
	if len(signatureEvents) == 0 {
		signatureEvents = nil
	}

	signatureDirs := viper.GetStringSlice("signatures-dir")

	analyze.Analyze(analyze.AnalyzeConfig{
		Rego:            rego,
		Input:           inputFile,
		SignatureDirs:   signatureDirs,
		SignatureEvents: signatureEvents,
	})
}

func bindViperFlag(cmd *cobra.Command, flag string) {
	err := viper.BindPFlag(flag, cmd.Flags().Lookup(flag))
	if err != nil {
		logger.Fatalw("Error binding viper flag", "flag", flag, "error", err)
	}
}

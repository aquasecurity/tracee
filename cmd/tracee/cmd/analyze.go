package cmd

import (
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aquasecurity/tracee/pkg/analyze"
	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/cmd/printer"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/logger"
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
		"Directory where to search for signatures in Go plugin (.so) format",
	)

	analyzeCmd.Flags().StringArrayP(
		"log",
		"l",
		[]string{"info"},
		"Logger options [debug|info|warn...]",
	)
}

var analyzeCmd = &cobra.Command{
	Use:     "analyze [--source file]",
	Aliases: []string{},
	Short:   "Analyze past events with signature events [Experimental]",
	Long: `Analyze allow you to explore signature events with past events.

Tracee can be used to collect events and store it in a file. This file can be used as input to analyze.

eg:
tracee --events ptrace --output=json:events.json
tracee analyze --events anti_debugging --source events.json`,
	PreRun: func(cmd *cobra.Command, args []string) {
		bindViperFlag(cmd, "events")
		bindViperFlag(cmd, "source")
		bindViperFlag(cmd, "output")
		bindViperFlag(cmd, "log")
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

	// placeholder printer for legacy mode
	p, err := printer.New(config.PrinterConfig{
		OutFile: os.Stdout,
		Kind:    "ignore",
	})

	if err != nil {
		logger.Fatalw("Failed to initialize initial printer")
	}

	isLegacy := false
	legacyOutFile := os.Stdout
	outputParts := strings.SplitN(outputArg, ":", 2)
	if len(outputParts) > 2 || len(outputParts) == 0 {
		logger.Fatalw("Failed to prepare output format (must be of format <format>:<optional_output_path>)")
	}

	outFormat := outputParts[0]
	outPath := ""
	if len(outputParts) > 1 {
		outPath = outputParts[1]
	}

	if outFormat == "legacy" {
		if outPath != "stdout" && outPath != "" {
			legacyOutFile, err = flags.CreateOutputFile(outPath)
			if err != nil {
				logger.Fatalw("Failed to create output file for legacy output")
			}
		}
		isLegacy = true
	} else {
		printerCfg, err := flags.PreparePrinterConfig(outFormat, outPath)
		if err != nil {
			logger.Fatalw("Failed to prepare output configuration", "error", err)
		}
		p, err = printer.New(printerCfg)
		if err != nil {
			logger.Fatalw("Failed to create printer", "error", err)
		}
	}

	// Signature directory command line flags

	signatureEvents := viper.GetStringSlice("events")
	// if no event was passed, load all events
	if len(signatureEvents) == 0 {
		signatureEvents = nil
	}

	signatureDirs := viper.GetStringSlice("signatures-dir")

	analyze.Analyze(analyze.Config{
		Source:          sourceFile,
		Printer:         p,
		Legacy:          isLegacy,
		LegacyOut:       legacyOutFile,
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

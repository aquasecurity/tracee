package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aquasecurity/tracee/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/pkg/cmd/initialize/sigs"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/findings"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/signatures/engine"
	"github.com/aquasecurity/tracee/pkg/signatures/signature"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

func init() {
	rootCmd.AddCommand(analyze)

	// flags

	// events
	analyze.Flags().StringArrayP(
		"events",
		"e",
		[]string{},
		"Define which signature events to load",
	)

	// signatures-dir
	analyze.Flags().StringArray(
		"signatures-dir",
		[]string{},
		"Directory where to search for signatures in OPA (.rego) and Go plugin (.so) formats",
	)

	// rego
	analyze.Flags().StringArray(
		"rego",
		[]string{},
		"Control event rego settings",
	)

	analyze.Flags().StringArrayP(
		"log",
		"l",
		[]string{"info"},
		"Logger options [debug|info|warn...]",
	)
}

var analyze = &cobra.Command{
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

	signatures, _, err := signature.Find(
		rego.RuntimeTarget,
		rego.PartialEval,
		viper.GetStringSlice("signatures-dir"),
		signatureEvents,
		rego.AIO,
	)

	if err != nil {
		logger.Fatalw("Failed to find signature event", "err", err)
	}

	if len(signatures) == 0 {
		logger.Fatalw("No signature event loaded")
	}

	logger.Infow(
		"Signatures loaded",
		"total", len(signatures),
		"signatures", getSigsNames(signatures),
	)

	_ = sigs.CreateEventsFromSignatures(events.StartSignatureID, signatures)

	engineConfig := engine.Config{
		Signatures:          signatures,
		SignatureBufferSize: 1000,
	}

	// two seperate contexts.
	// 1. signal notifiable context that can terminate both analyze and engine work
	// 2. signal solely to notify internally inside analyze once file input is over
	signalCtx, _ := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	fileReadCtx, stop := context.WithCancel(signalCtx)

	engineOutput := make(chan *detect.Finding)
	engineInput := make(chan protocol.Event)

	source := engine.EventSources{Tracee: engineInput}
	sigEngine, err := engine.NewEngine(engineConfig, source, engineOutput)
	if err != nil {
		logger.Fatalw("Failed to create engine", "err", err)
	}

	err = sigEngine.Init()
	if err != nil {
		logger.Fatalw("failed to initialize signature engine", "err", err)
	}

	go sigEngine.Start(signalCtx)

	// producer
	go produce(fileReadCtx, stop, inputFile, engineInput)

	// consumer
	for {
		select {
		case finding, ok := <-engineOutput:
			if !ok {
				return
			}
			process(finding)
		case <-fileReadCtx.Done():
			// ensure the engineInput channel will be closed
			goto drain
		case <-signalCtx.Done():
			// ensure the engineInput channel will be closed
			goto drain
		}
	}
drain:
	// drain
	defer close(engineInput)
	for {
		select {
		case finding, ok := <-engineOutput:
			if !ok {
				return
			}

			process(finding)
		default:
			return
		}
	}
}

func produce(ctx context.Context, cancel context.CancelFunc, inputFile *os.File, engineInput chan<- protocol.Event) {
	scanner := bufio.NewScanner(inputFile)
	scanner.Split(bufio.ScanLines)
	for {
		select {
		case <-ctx.Done():
			// if terminated from above
			return
		default:
			if !scanner.Scan() { // if EOF or error close the done channel and return
				if err := scanner.Err(); err != nil {
					logger.Errorw("Error while scanning input file", "error", err)
				}
				// terminate analysis here and proceed to draining
				cancel()
				return
			}

			var e trace.Event
			err := json.Unmarshal(scanner.Bytes(), &e)
			if err != nil {
				logger.Fatalw("Failed to unmarshal event", "err", err)
			}
			engineInput <- e.ToProtocol()
		}
	}
}

func process(finding *detect.Finding) {
	event, err := findings.FindingToEvent(finding)
	if err != nil {
		logger.Fatalw("Failed to convert finding to event", "err", err)
	}

	jsonEvent, err := json.Marshal(event)
	if err != nil {
		logger.Fatalw("Failed to json marshal event", "err", err)
	}

	fmt.Println(string(jsonEvent))
}

func bindViperFlag(cmd *cobra.Command, flag string) {
	err := viper.BindPFlag(flag, cmd.Flags().Lookup(flag))
	if err != nil {
		logger.Fatalw("Error binding viper flag", "flag", flag, "error", err)
	}
}

func getSigsNames(signatures []detect.Signature) []string {
	var sigNames []string
	for _, sig := range signatures {
		sigMeta, err := sig.GetMetadata()
		if err != nil {
			logger.Warnw("Failed to get signature metadata", "err", err)
			continue
		}
		sigNames = append(sigNames, sigMeta.Name)
	}
	return sigNames
}

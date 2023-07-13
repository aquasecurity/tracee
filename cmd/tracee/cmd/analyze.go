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
	"github.com/aquasecurity/tracee/pkg/cmd/initialize"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/events"
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

	// TODO: decide if we want to bind this flag to viper, since we already have a similar
	// flag in rootCmd, conflicting with each other.
	// The same goes for the other flags (signatures-dir, rego), also in rootCmd.
	//
	// err := viper.BindPFlag("events", analyze.Flags().Lookup("events"))
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "Error: %s\n", err)
	// 	os.Exit(1)
	// }

	// signatures-dir
	analyze.Flags().StringArray(
		"signatures-dir",
		[]string{},
		"Directory where to search for signatures in CEL (.yaml), OPA (.rego), and Go plugin (.so) formats",
	)
	// err = viper.BindPFlag("signatures-dir", analyze.Flags().Lookup("signatures-dir"))
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "Error: %s\n", err)
	// 	os.Exit(1)
	// }

	// rego
	analyze.Flags().StringArray(
		"rego",
		[]string{},
		"Control event rego settings",
	)
	// err = viper.BindPFlag("rego", analyze.Flags().Lookup("rego"))
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "Error: %s\n", err)
	// 	os.Exit(1)
	// }
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
	Run: func(cmd *cobra.Command, args []string) {
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

		sigs, err := signature.Find(
			rego.RuntimeTarget,
			rego.PartialEval,
			viper.GetStringSlice("signatures-dir"),
			signatureEvents,
			rego.AIO,
		)

		if err != nil {
			logger.Fatalw("Failed to find signature event", "err", err)
		}

		if len(sigs) == 0 {
			logger.Fatalw("No signature event loaded")
		}

		fmt.Printf("Loading %d signature events\n", len(sigs))

		initialize.CreateEventsFromSignatures(events.StartSignatureID, sigs)

		engineConfig := engine.Config{
			Signatures:          sigs,
			SignatureBufferSize: 1000,
		}

		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()

		engineOutput := make(chan detect.Finding)
		engineInput := make(chan protocol.Event)
		producerFinished := make(chan interface{})

		source := engine.EventSources{Tracee: engineInput}
		sigEngine, err := engine.NewEngine(engineConfig, source, engineOutput)
		if err != nil {
			logger.Fatalw("Failed to create engine", "err", err)
		}
		go sigEngine.Start(ctx)

		// producer
		go produce(ctx, producerFinished, inputFile, engineInput)

		// consumer
		for {
			select {
			case finding := <-engineOutput:
				process(finding)
			case <-producerFinished:
				goto drain // producer finished, drain and process all remaining events
			case <-ctx.Done():
				goto drain
			}
		}

	drain:
		// drain
		for {
			select {
			case finding := <-engineOutput:
				process(finding)
			default:
				return
			}
		}
	},
	DisableFlagsInUseLine: true,
}

func produce(ctx context.Context, done chan interface{}, inputFile *os.File, engineInput chan protocol.Event) {
	scanner := bufio.NewScanner(inputFile)
	scanner.Split(bufio.ScanLines)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			if !scanner.Scan() { // if EOF or error close the done channel and return
				close(done)
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

func process(finding detect.Finding) {
	event, err := tracee.FindingToEvent(finding)
	if err != nil {
		logger.Fatalw("Failed to convert finding to event", "err", err)
	}

	jsonEvent, err := json.Marshal(event)
	if err != nil {
		logger.Fatalw("Failed to json marshal event", "err", err)
	}

	fmt.Println(string(jsonEvent))
}

package analyze

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/aquasecurity/tracee/pkg/cmd/initialize/sigs"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/findings"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/signatures/engine"
	"github.com/aquasecurity/tracee/pkg/signatures/rego"
	"github.com/aquasecurity/tracee/pkg/signatures/signature"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type AnalyzeConfig struct {
	Rego            rego.Config
	Input           *os.File
	SignatureDirs   []string
	SignatureEvents []string
}

func Analyze(cfg AnalyzeConfig) {
	signatures, _, err := signature.Find(
		cfg.Rego.RuntimeTarget,
		cfg.Rego.PartialEval,
		cfg.SignatureDirs,
		cfg.SignatureEvents,
		cfg.Rego.AIO,
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

	sigNamesToIds := sigs.CreateEventsFromSignatures(events.StartSignatureID, signatures)

	engineConfig := engine.Config{
		Signatures:          signatures,
		SignatureBufferSize: 1000,
		Enabled:             true, // simulate tracee single binary mode
		SigNameToEventID:    sigNamesToIds,
		ShouldDispatchEvent: func(eventIdInt32 int32) bool {
			// in analyze mode we don't need to filter by policy
			return true
		},
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
	go produce(fileReadCtx, stop, cfg.Input, engineInput)

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

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
	"github.com/aquasecurity/tracee/pkg/cmd/printer"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/findings"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/signatures/engine"
	"github.com/aquasecurity/tracee/pkg/signatures/signature"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

type Config struct {
	Source          *os.File
	Printer         printer.EventPrinter
	Legacy          bool // TODO: remove once tracee-rules legacy is over
	LegacyOut       *os.File
	SignatureDirs   []string
	SignatureEvents []string
}

func Analyze(cfg Config) {
	signatures, _, err := signature.Find(cfg.SignatureDirs, cfg.SignatureEvents)

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

	// decide process output
	var process func(*detect.Finding)
	if cfg.Legacy {
		process = processLegacy(cfg.LegacyOut)
	} else {
		process = processWithPrinter(cfg.Printer)
	}

	// producer
	go produce(fileReadCtx, stop, cfg.Source, engineInput)

	cfg.Printer.Preamble()
	defer cfg.Printer.Close()
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

func processWithPrinter(p printer.EventPrinter) func(finding *detect.Finding) {
	return func(finding *detect.Finding) {
		event, err := findings.FindingToEvent(finding)
		if err != nil {
			logger.Fatalw("Failed to convert finding to event", "err", err)
		}

		p.Print(*event)
	}
}

func processLegacy(outF *os.File) func(finding *detect.Finding) {
	return func(finding *detect.Finding) {
		evt, ok := finding.Event.Payload.(trace.Event)
		if !ok {
			logger.Fatalw("Failed to extract finding event payload (legacy output)")
		}
		out := legacyOutput{
			Data:        finding.GetData(),
			Event:       evt,
			SigMetadata: finding.SigMetadata,
		}

		outBytes, err := json.Marshal(out)
		if err != nil {
			logger.Fatalw("Failed to convert finding to legacy output", "err", err)
		}

		_, err = fmt.Fprintln(outF, string(outBytes))
		if err != nil {
			logger.Errorw("failed to write legacy output to file", "err", err)
		}
	}
}

type legacyOutput struct {
	Data        map[string]any           `json:"Data,omitempty"`
	Event       trace.Event              `json:"Context,omitempty"`
	SigMetadata detect.SignatureMetadata `json:"SigMetadata,omitempty"`
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

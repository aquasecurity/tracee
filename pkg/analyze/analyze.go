package analyze

import (
	"bufio"
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/cmd/printer"
	"github.com/aquasecurity/tracee/pkg/datastores"
	"github.com/aquasecurity/tracee/pkg/detectors"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/policy"
	"google.golang.org/protobuf/encoding/protojson"
)

type Config struct {
	Source            *os.File
	Printer           printer.EventPrinter
	Detectors         []detection.EventDetector
	PolicyManager     *policy.Manager
	EnrichmentOptions *detectors.EnrichmentOptions
}

func Analyze(cfg Config) {
	if len(cfg.Detectors) == 0 {
		logger.Fatalw("No detectors available")
	}

	logger.Infow(
		"Detectors loaded",
		"total", len(cfg.Detectors),
	)

	// Detector events are already registered in cobra.go before replay mode
	// Create detector engine
	detectorEngine := detectors.NewEngine(cfg.PolicyManager, cfg.EnrichmentOptions)

	// Register all detectors with the engine
	// For analyze mode, we need to create detector params
	// Since we don't have datastores in analyze mode, create empty registry
	// Create a logger adapter that wraps tracee's logger
	loggerAdapter := &loggerAdapter{}
	params := detection.DetectorParams{
		Logger:     loggerAdapter,
		Config:     detection.NewEmptyDetectorConfig(),
		DataStores: datastores.NewRegistry(),
	}

	for _, detector := range cfg.Detectors {
		if err := detectorEngine.RegisterDetector(detector, params); err != nil {
			logger.Errorw("Failed to register detector", "error", err, "detector", detector.GetDefinition().ID)
			continue
		}
		// Enable all detectors for analyze mode
		if err := detectorEngine.EnableDetector(detector.GetDefinition().ID); err != nil {
			logger.Errorw("Failed to enable detector", "error", err, "detector", detector.GetDefinition().ID)
		}
	}

	// Create contexts for signal handling
	signalCtx, _ := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	fileReadCtx, stop := context.WithCancel(signalCtx)

	// Producer: read events from file (protobuf JSON format)
	fromFile := make(chan *v1beta1.Event, 100)
	go produce(fileReadCtx, stop, cfg.Source, fromFile)

	cfg.Printer.Preamble()
	defer cfg.Printer.Close()

	count := 0
	// Consumer: process events and dispatch to detectors
	for {
		select {
		case event, ok := <-fromFile:
			if !ok {
				logger.Debugw("Finished processing file", "detector_outputs", count)
				return
			}

			// Translate protobuf event ID to internal event ID
			// Events from file have protobuf event IDs, but dispatch map uses internal IDs
			protobufEventID := event.Id
			internalEventID := events.TranslateFromProtoEventID(protobufEventID)
			event.Id = v1beta1.EventId(internalEventID)

			logger.Debugw("Processing event", "event", event.Name, "protobuf_id", protobufEventID, "internal_id", internalEventID)

			// Check if this event was selected by --events flag
			// If so, print it before dispatching to detectors
			if cfg.PolicyManager != nil && cfg.PolicyManager.IsEventSelected(internalEventID) {
				cfg.Printer.Print(event)
			}

			// Dispatch to detector engine (event is already v1beta1.Event)
			detectorOutputs, err := detectorEngine.DispatchToDetectors(signalCtx, event)
			if err != nil {
				logger.Errorw("Failed to dispatch event to detectors", "error", err, "event", event.Name)
				continue
			}

			if len(detectorOutputs) > 0 {
				logger.Debugw("Detector outputs produced", "count", len(detectorOutputs), "event", event.Name)
			}

			// Print detector outputs
			for _, output := range detectorOutputs {
				count++
				cfg.Printer.Print(output)
			}

			// Handle detector chains: process detector outputs that might trigger other detectors
			// Use breadth-first processing to handle chains
			queue := make([]*v1beta1.Event, 0, len(detectorOutputs))
			queue = append(queue, detectorOutputs...)

			for len(queue) > 0 {
				chainEvent := queue[0]
				queue = queue[1:]

				// Dispatch chain event to detectors
				chainOutputs, err := detectorEngine.DispatchToDetectors(signalCtx, chainEvent)
				if err != nil {
					logger.Errorw("Failed to dispatch chain event to detectors", "error", err, "event", chainEvent.Name)
					continue
				}

				// Print chain outputs and add to queue for further processing
				for _, output := range chainOutputs {
					count++
					cfg.Printer.Print(output)
					queue = append(queue, output)
				}
			}

		case <-fileReadCtx.Done():
			// File reading finished, drain remaining events
			goto drain
		case <-signalCtx.Done():
			// Signal received, drain remaining events
			goto drain
		}
	}

drain:
	// Drain remaining events from file
	for {
		select {
		case event, ok := <-fromFile:
			if !ok {
				logger.Debugw("Drained file events", "detector_outputs", count)
				return
			}

			detectorOutputs, err := detectorEngine.DispatchToDetectors(signalCtx, event)
			if err != nil {
				logger.Errorw("Failed to dispatch event to detectors", "error", err, "event", event.Name)
				continue
			}

			for _, output := range detectorOutputs {
				count++
				cfg.Printer.Print(output)
			}
		default:
			logger.Debugw("Drained all events", "detector_outputs", count)
			return
		}
	}
}

func produce(ctx context.Context, cancel context.CancelFunc, inputFile *os.File, eventChan chan<- *v1beta1.Event) {
	scanner := bufio.NewScanner(inputFile)
	scanner.Split(bufio.ScanLines)
	unmarshaler := protojson.UnmarshalOptions{
		DiscardUnknown: true, // Ignore unknown fields for forward compatibility
	}
	count := 0
	for {
		select {
		case <-ctx.Done():
			// if terminated from above
			return
		default:
			if !scanner.Scan() { // if EOF or error close the done channel and return
				if err := scanner.Err(); err != nil {
					// Not EOF
					logger.Errorw("Error while scanning input file", "error", err, "line", count)
				}
				// terminate analysis here and proceed to draining
				cancel()
				close(eventChan)
				return
			}
			count++

			var e v1beta1.Event
			err := unmarshaler.Unmarshal(scanner.Bytes(), &e)
			if err != nil {
				logger.Errorw("Failed to unmarshal event", "error", err, "line", count)
				continue
			}
			eventChan <- &e
		}
	}
}

// loggerAdapter adapts tracee's logger to detection.Logger interface
type loggerAdapter struct{}

func (l *loggerAdapter) Debugw(msg string, keysAndValues ...any) {
	logger.Debugw(msg, keysAndValues...)
}

func (l *loggerAdapter) Infow(msg string, keysAndValues ...any) {
	logger.Infow(msg, keysAndValues...)
}

func (l *loggerAdapter) Warnw(msg string, keysAndValues ...any) {
	logger.Warnw(msg, keysAndValues...)
}

func (l *loggerAdapter) Errorw(msg string, keysAndValues ...any) {
	logger.Errorw(msg, keysAndValues...)
}

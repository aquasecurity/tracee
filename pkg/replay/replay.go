package replay

import (
	"bufio"
	"context"
	"os"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/cmd/printer"
	"github.com/aquasecurity/tracee/pkg/datastores"
	"github.com/aquasecurity/tracee/pkg/detectors"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/policy"
)

const (
	// eventChanBufferSize decouples file reading from event dispatch: the
	// producer keeps parsing lines while the consumer runs detectors on
	// already-parsed events. The exact size is not critical; 100 events is
	// enough to absorb dispatch latency spikes while keeping memory bounded.
	eventChanBufferSize = 100

	// Tracee JSON events routinely exceed bufio.Scanner's 64KB default line
	// limit (argument data, environment variables, stack traces), which would
	// otherwise abort the replay with "token too long".
	scannerInitialBufferSize = 1024 * 1024      // 1MB
	scannerMaxLineSize       = 16 * 1024 * 1024 // 16MB

	// maxDetectorChainDepth bounds detector chain processing, mirroring the
	// live pipeline (see pkg/ebpf/events_pipeline.go). Expected chains are
	// raw event → derived event → threat event → threat event; without the
	// bound, mutually-triggering detectors would loop forever.
	maxDetectorChainDepth = 5

	// maxEventDataEntries bounds the data entries accepted per replayed
	// event. Real tracee events carry at most a few dozen; a crafted line
	// of millions of empty entries amplifies ~30x in heap and is retained
	// per channel slot, so unbounded entries allow memory exhaustion from
	// an untrusted capture file. Generous headroom over any real event.
	maxEventDataEntries = 1024

	// maxLoggedErrorLen bounds attacker-influenced strings in log output:
	// unmarshal errors embed field values, and captured events legitimately
	// contain secrets (e.g. credentials in recorded environment variables).
	maxLoggedErrorLen = 256
)

// Config carries everything Replay needs; the caller owns Source's lifetime.
type Config struct {
	Source            *os.File                     // JSON Lines event file to replay
	Printer           printer.EventPrinter         // Destination for detector outputs
	Detectors         []detection.EventDetector    // Detectors to register and enable
	PolicyManager     *policy.Manager              // Must have the detector events enabled
	EnrichmentOptions *detectors.EnrichmentOptions // Enrichment is not supported yet; pass disabled options
}

// Replay reads events from cfg.Source (JSON Lines, as produced by
// tracee --output json:file) and dispatches them to the configured detectors,
// printing detector outputs only. It returns when the file is exhausted or
// the given context is cancelled.
func Replay(ctx context.Context, cfg Config) error {
	if len(cfg.Detectors) == 0 {
		return errfmt.Errorf("no detectors available")
	}

	logger.Infow(
		"Detectors loaded",
		"total", len(cfg.Detectors),
	)

	detectorEngine := detectors.NewEngine(cfg.PolicyManager, cfg.EnrichmentOptions)

	// Datastores are not supported in replay mode yet, so detectors get an
	// empty registry (detectors requiring one fail registration below)
	params := detection.DetectorParams{
		Logger:     &loggerAdapter{},
		Config:     detection.NewEmptyDetectorConfig(),
		DataStores: datastores.NewRegistry(),
	}

	for _, detector := range cfg.Detectors {
		if err := detectorEngine.RegisterDetector(detector, params); err != nil {
			logger.Errorw("Failed to register detector", "error", err, "detector", detector.GetDefinition().ID)
			continue
		}
		// Enable all detectors for replay mode
		if err := detectorEngine.EnableDetector(detector.GetDefinition().ID); err != nil {
			logger.Errorw("Failed to enable detector", "error", err, "detector", detector.GetDefinition().ID)
		}
	}

	// Producer: read events from file (protobuf JSON format)
	fromFile := make(chan *v1beta1.Event, eventChanBufferSize)
	scanErr := make(chan error, 1)
	go produce(ctx, cfg.Source, fromFile, scanErr)

	cfg.Printer.Preamble()
	defer cfg.Printer.Close()

	// Consumer: process events and dispatch to detectors
	for {
		select {
		case event, ok := <-fromFile:
			if !ok {
				// A scan error is terminal for the whole file: everything
				// after the failing point was dropped, so fail loudly
				// instead of reporting a successful partial replay
				select {
				case err := <-scanErr:
					return errfmt.Errorf("failed reading replay file: %v", err)
				default:
				}
				logger.Infow("Finished processing file")
				return nil
			}
			processEvent(ctx, detectorEngine, cfg.Printer, event)
		case <-ctx.Done():
			// Cancelled (e.g. SIGINT): best-effort process what the producer
			// already buffered, then stop.
			for {
				select {
				case event, ok := <-fromFile:
					if !ok {
						return nil
					}
					processEvent(ctx, detectorEngine, cfg.Printer, event)
				default:
					logger.Debugw("Drained all events")
					// Discard the rest until the producer closes the channel,
					// so the caller cannot close the file under a live scanner
					for {
						if _, ok := <-fromFile; !ok {
							return nil
						}
					}
				}
			}
		}
	}
}

// processEvent translates, filters and dispatches a single replayed event,
// then processes detector outputs level by level so that detector chains
// (outputs triggering other detectors) are explored up to
// maxDetectorChainDepth, as in the live pipeline. Only detector outputs are
// printed.
func processEvent(ctx context.Context, detectorEngine *detectors.Engine, p printer.EventPrinter, event *v1beta1.Event) {
	internalEventID := translateEventID(event)

	// Filter out detector events - only low-level events should be replayed.
	// The range check makes unregistered IDs in the detector range fail
	// closed (GetDefinitionByID returns Undefined for them, which would
	// otherwise pass the IsDetector test).
	eventDef := events.Core.GetDefinitionByID(internalEventID)
	if eventDef.IsDetector() ||
		(internalEventID >= events.StartDetectorID && internalEventID <= events.MaxDetectorID) {
		return
	}

	logger.Debugw("Processing event", "event", event.Name, "internal_id", internalEventID)

	queue := dispatchAndPrint(ctx, detectorEngine, p, event)

	for depth := 0; depth < maxDetectorChainDepth && len(queue) > 0 && ctx.Err() == nil; depth++ {
		var nextDepth []*v1beta1.Event
		for _, chainEvent := range queue {
			nextDepth = append(nextDepth, dispatchAndPrint(ctx, detectorEngine, p, chainEvent)...)
		}
		queue = nextDepth
	}

	if len(queue) > 0 && ctx.Err() == nil {
		logger.Errorw("Exceeded max detector chain depth",
			"max_depth", maxDetectorChainDepth,
			"remaining_events", len(queue))
	}
}

// dispatchAndPrint dispatches one event to the detector engine and prints the
// resulting detector outputs, returning them for chain processing.
func dispatchAndPrint(ctx context.Context, detectorEngine *detectors.Engine, p printer.EventPrinter, event *v1beta1.Event) []*v1beta1.Event {
	outputs, err := detectorEngine.DispatchToDetectors(ctx, event)
	if err != nil {
		logger.Errorw("Failed to dispatch event to detectors", "error", err, "event", event.Name)
		return nil
	}

	if len(outputs) > 0 {
		logger.Debugw("Detector outputs produced", "count", len(outputs), "event", event.Name)
	}

	for _, output := range outputs {
		p.Print(output)
	}
	return outputs
}

// translateEventID translates protobuf event ID to internal event ID and updates the event
// Events from file have protobuf event IDs, but dispatch map uses internal IDs
func translateEventID(event *v1beta1.Event) events.ID {
	protobufEventID := event.Id
	internalEventID := events.TranslateFromProtoEventID(protobufEventID)
	event.Id = v1beta1.EventId(internalEventID)
	return internalEventID
}

// produce reads JSON Lines from inputFile and sends the parsed events to
// eventChan. It closes eventChan when done and returns early if ctx is
// cancelled. Scan errors (oversized line, I/O failure) are terminal for the
// scanner — the rest of the file is unreadable — so they are reported through
// scanErr (buffered, capacity 1) for the consumer to surface.
func produce(ctx context.Context, inputFile *os.File, eventChan chan<- *v1beta1.Event, scanErr chan<- error) {
	defer close(eventChan)

	scanner := bufio.NewScanner(inputFile)
	scanner.Buffer(make([]byte, scannerInitialBufferSize), scannerMaxLineSize)
	scanner.Split(bufio.ScanLines)
	unmarshaler := protojson.UnmarshalOptions{
		DiscardUnknown: true, // Ignore unknown fields for forward compatibility
	}
	count := 0
	for scanner.Scan() {
		if ctx.Err() != nil {
			return
		}
		count++

		var e v1beta1.Event
		err := unmarshaler.Unmarshal(scanner.Bytes(), &e)
		if err != nil {
			logger.Errorw("Failed to unmarshal event", "error", truncateForLog(err.Error()), "line", count)
			continue
		}

		if len(e.Data) > maxEventDataEntries {
			logger.Warnw("Skipping event with too many data entries",
				"line", count, "entries", len(e.Data), "max", maxEventDataEntries)
			continue
		}

		select {
		case eventChan <- &e:
		case <-ctx.Done():
			// Consumer is gone; do not block on a full channel forever
			return
		}
	}
	if err := scanner.Err(); err != nil {
		scanErr <- errfmt.Errorf("line %d: %v", count+1, err)
	}
}

// truncateForLog bounds a string destined for log output
func truncateForLog(s string) string {
	if len(s) > maxLoggedErrorLen {
		return s[:maxLoggedErrorLen] + "...(truncated)"
	}
	return s
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

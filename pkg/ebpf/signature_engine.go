package ebpf

import (
	"context"
	"time"

	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/datastores/container"
	"github.com/aquasecurity/tracee/pkg/datastores/dns"
	"github.com/aquasecurity/tracee/pkg/datastores/process"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/findings"
	"github.com/aquasecurity/tracee/pkg/signatures/engine"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

// engineEvents is the signature engine pipeline stage. For each received event, it feeds
// a copy to the signature engine for rule evaluation, and forwards the original event
// downstream. Findings produced by the engine are converted back into pipeline events
// and also forwarded downstream. Uses a select loop to multiplex between the input
// channel and engine output events.
func (t *Tracee) engineEvents(in <-chan *events.PipelineEvent) (<-chan *events.PipelineEvent, <-chan error) {
	out := make(chan *events.PipelineEvent, t.config.Buffers.Pipeline)
	errc := make(chan error, 1)

	engineOutput := make(chan *detect.Finding, t.config.Buffers.Pipeline)
	engineInput := make(chan protocol.Event, t.config.Buffers.Pipeline)
	engineOutputEvents := make(chan *events.PipelineEvent, t.config.Buffers.Pipeline)
	source := engine.EventSources{Tracee: engineInput}

	// Prepare built in data sources
	t.config.EngineConfig.DataSources = append(t.config.EngineConfig.DataSources, t.PrepareBuiltinDataSources()...)

	sigEngine, err := engine.NewEngine(t.config.EngineConfig, source, engineOutput)
	if err != nil {
		logger.Fatalw("failed to start signature engine in \"everything is an event\" mode", "error", err)
	}
	t.sigEngine = sigEngine

	if t.MetricsEnabled() {
		err := t.sigEngine.Stats().RegisterPrometheus()
		if err != nil {
			logger.Errorw("Registering signature engine prometheus metrics", "error", err)
		}
	}

	err = t.sigEngine.Init()
	if err != nil {
		logger.Fatalw("failed to initialize signature engine in \"everything is an event\" mode", "error", err)
	}

	// Start the signature engine in a goroutine.
	// The engine drains via channel close, not context cancellation.
	// context.Background() is inert (Done() returns nil), so matchHandler's
	// ctx.Done() select case never fires -- which is correct here because the
	// converter goroutine always consumes engine.output while the engine runs.
	engineDone := make(chan struct{})
	go func() {
		t.sigEngine.Start(context.Background())
		close(engineDone)
	}()

	// TODO: in the upcoming releases, the rule engine should be changed to receive trace.Event,
	// and return a trace.Event, which should remove the necessity of converting trace.Event to protocol.Event,
	// and converting detect.Finding into trace.Event

	go func() {
		defer close(out)
		defer close(errc)

		// feedEngine feeds an event to the rules engine
		feedEngine := func(event *events.PipelineEvent) {
			if event == nil {
				return // might happen during initialization (ctrl+c seg faults)
			}

			// Proto-native events (from detectors/derivers) bypass the signature engine
			// They don't have a trace.Event, only ProtoEvent
			if event.Event == nil {
				out <- event
				return
			}

			id := event.EventID

			// if the event is NOT marked as submit, it is not sent to the rules engine
			if !t.policyManager.IsEventToSubmit(id) {
				return
			}

			// Get a copy of event before parsing it or sending it down the pipeline.
			// This prevents race conditions between the sink stage (which modifies events
			// for output formatting) and the signature engine (which needs raw event data).
			eventCopy := *event.Event

			// Deep copy the Args slice to prevent race conditions during argument parsing
			eventCopy.Args = make([]trace.Argument, len(event.Args))
			copy(eventCopy.Args, event.Args)

			// Ensure ArgsNum matches the actual Args slice length for consistency
			eventCopy.ArgsNum = len(eventCopy.Args)

			// Send original event to sink stage (blocking - sink always consumes)
			out <- event

			// Send protocol event to signature engine (blocking - engine consumes
			// until engineInput is closed below)
			engineInput <- eventCopy.ToProtocol()
		}

		// We use a select loop (not for-range) to multiplex between pipeline
		// input and engine output (findings converted back to pipeline events).
		// All sends are blocking because downstream (sink) always consumes,
		// so no event that entered the pipeline will be dropped.
		for {
			select {
			case event, ok := <-in:
				if !ok {
					goto drain
				}
				feedEngine(event)
			case event := <-engineOutputEvents:
				// Feed findings back through feedEngine so they are sent to
				// both the sink (out) and the signature engine (engineInput).
				// This enables signature chaining: one signature's finding
				// can trigger another signature.
				feedEngine(event)
			}
		}

	drain:
		// Shutdown sequence: we must drain deterministically to avoid deadlock.
		//
		// The channels form a cycle:
		//   engineInput -> sigEngine -> engineOutput -> converter -> engineOutputEvents -> here
		//
		// Phase 1: Keep signature chaining alive during drain. Re-feed findings
		// back to the engine via feedEngine (which sends to both out and
		// engineInput). Use a quiescence timer to detect when the chain has
		// settled: if no new finding arrives within the timeout, all in-flight
		// events have been fully processed. The timeout (200ms) is far above the
		// round-trip latency of one event through the cycle (~5ms).
		//
		// Phase 2: Break the cycle by closing engineInput, then wait for each
		// downstream stage to finish while draining engineOutputEvents.

		const quiescentTimeout = 200 * time.Millisecond
		quiescentTimer := time.NewTimer(quiescentTimeout)
		for {
			select {
			case event := <-engineOutputEvents:
				feedEngine(event)
				// Reset timer: a new finding means the chain is still active
				quiescentTimer.Reset(quiescentTimeout)
			case <-quiescentTimer.C:
				// No findings for quiescentTimeout: assuming the chain has fully settled.
				goto stopEngine
			}
		}

	stopEngine:
		quiescentTimer.Stop()

		// Phase 2: Close engineInput so the sig engine finishes processing.
		close(engineInput)

		// Step 2: Wait for the sig engine to finish processing its remaining events.
		// While waiting, keep draining engineOutputEvents to prevent the converter
		// from blocking on its send (which would prevent the engine from writing to
		// engineOutput, which would prevent engineDone from closing).
		for {
			select {
			case <-engineDone:
				// Engine finished: close engineOutput so the converter goroutine
				// finishes its for-range loop and closes engineOutputEvents.
				close(engineOutput)
				goto drainConverter
			case event := <-engineOutputEvents:
				if event != nil {
					out <- event
				}
			}
		}

	drainConverter:
		// Step 3: Drain engineOutputEvents until the converter goroutine closes it.
		// This is a blocking drain (for-range) that guarantees every finding produced
		// by the engine is forwarded downstream. No event is dropped.
		for event := range engineOutputEvents {
			if event != nil {
				out <- event
			}
		}
	}()

	// Converter goroutine: reads findings from the signature engine, converts
	// them to pipeline events, and sends them to engineOutputEvents. Closes
	// engineOutputEvents when engineOutput is closed (which signals that the
	// engine has finished and no more findings will arrive).
	go func() {
		defer close(engineOutputEvents)

		for finding := range engineOutput {
			if finding.Event.Payload == nil {
				continue // might happen during initialization (ctrl+c seg faults)
			}

			traceEvent, err := findings.FindingToEvent(finding)
			if err != nil {
				t.handleError(err)
				continue
			}

			// Wrap finding event in PipelineEvent
			event := events.NewPipelineEvent(traceEvent)
			if t.matchPolicies(event) == 0 {
				_ = t.stats.EventsFiltered.Increment()
				continue
			}

			engineOutputEvents <- event
		}
	}()

	return out, errc
}

// PrepareBuiltinDataSources returns a list of all data sources tracee makes available built-in
func (t *Tracee) PrepareBuiltinDataSources() []detect.DataSource {
	datasources := []detect.DataSource{}

	// Containers Data Source
	datasources = append(datasources, container.NewDataSource(t.dataStoreRegistry.GetContainerManager()))

	// DNS Data Source
	if t.config.DNSStore.Enable {
		datasources = append(datasources, dns.NewDataSource(t.dataStoreRegistry.GetDNSCache()))
	}

	// Process Tree Data Source
	switch t.config.ProcessStore.Source {
	case process.SourceNone:
	default:
		datasources = append(datasources, process.NewDataSource(t.dataStoreRegistry.GetProcessTree()))
	}

	return datasources
}

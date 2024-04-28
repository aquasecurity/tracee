package analyze

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/signatures/engine"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

// RunPipeline run the analyze mode pipeline.
// It consists of minimal steps, as it is only required to read the events, pass
// them to the signatures and print the results.
func RunPipeline(signatures []detect.Signature, chosenEvents []string, inputFile *os.File) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	engineOutput := make(chan *detect.Finding)
	engineInput := make(chan protocol.Event, 100)
	printInput := make(chan protocol.Event, 100)

	engineConfig := engine.Config{
		Signatures:          signatures,
		SignatureBufferSize: 1000,
	}

	source := engine.EventSources{Tracee: engineInput}
	sigEngine, err := engine.NewEngine(engineConfig, source, engineOutput)
	if err != nil {
		logger.Fatalw("Failed to create engine", "err", err)
	}

	err = sigEngine.Init()
	if err != nil {
		logger.Fatalw("failed to initialize signature engine", "err", err)
	}

	wg := sync.WaitGroup{}

	produceOutput := produce(ctx, &wg, inputFile)
	sigsEvents := process(ctx, &wg, engineOutput)
	printEvents(ctx, &wg, chosenEvents, printInput)

	go func() {
		for {
			select {
			case event, ok := <-produceOutput:
				if !ok {
					stop()
				}
				printInput <- event
				engineInput <- event
			case event := <-sigsEvents:
				printInput <- event
				engineInput <- event
			case <-ctx.Done():
				return
			}
		}
	}()

	go sigEngine.Start(ctx)
	wg.Wait()
}

// produce starts a goroutine that read the given file and produce events from its content.
// The events produced this way are passed through returned channel.
func produce(ctx context.Context, wg *sync.WaitGroup, inputFile *os.File) <-chan protocol.Event {
	outChannel := make(chan protocol.Event, 100)

	scanner := bufio.NewScanner(inputFile)
	scanner.Split(bufio.ScanLines)
	wg.Add(1)
	go func() {
		// ensure the outChannel channel will be closed
		defer close(outChannel)
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			default:
				if !scanner.Scan() { // if EOF or error close the done channel and return
					return
				}

				var e trace.Event
				err := json.Unmarshal(scanner.Bytes(), &e)
				if err != nil {
					logger.Fatalw("Failed to unmarshal event", "err", err)
				}
				outChannel <- e.ToProtocol()
			}
		}
	}()
	return outChannel
}

// process starts a goroutine that transforms the given findings of signatures to events and
// move them on in the pipeline.
func process(ctx context.Context, wg *sync.WaitGroup, engineOutput <-chan *detect.Finding) <-chan protocol.Event {
	sigsEvents := make(chan protocol.Event, 100)
	wg.Add(1)
	go func() {
		defer wg.Done()
		// consumer
		for {
			select {
			case finding, ok := <-engineOutput:
				if !ok {
					return
				}
				event, err := tracee.FindingToEvent(finding)
				if err != nil {
					logger.Fatalw("Failed to convert finding to event", "err", err)
				}
				sigsEvents <- event.ToProtocol()
			case <-ctx.Done():
				goto drain
			}
		}
	drain:
		// drain
		for {
			select {
			case finding, ok := <-engineOutput:
				if !ok {
					return
				}
				event, err := tracee.FindingToEvent(finding)
				if err != nil {
					logger.Fatalw("Failed to convert finding to event", "err", err)
				}
				sigsEvents <- event.ToProtocol()
			default:
				return
			}
		}
	}()
	return sigsEvents
}

// printEvents starts a goroutine that prints the received events if they are chosen.
// It is similar to the Sink stage in the normal pipeline.
func printEvents(ctx context.Context, wg *sync.WaitGroup, eventsToPrint []string, eventsInput <-chan protocol.Event) {
	wg.Add(1)

	eventsToPrintMap := make(map[string]struct{}, len(eventsToPrint))
	for _, eventName := range eventsToPrint {
		eventsToPrintMap[eventName] = struct{}{}
	}
	go func() {
		defer wg.Done()
		// consumer
		for {
			select {
			case event, ok := <-eventsInput:
				if !ok {
					return
				}
				if _, ok := eventsToPrintMap[event.Selector().Name]; ok {
					eventObj := event.Payload.(trace.Event)
					printEvent(&eventObj)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

// printEvent prints the event to stdout as json
func printEvent(event *trace.Event) {
	jsonEvent, err := json.Marshal(event)
	if err != nil {
		logger.Fatalw("Failed to json marshal event", "err", err)
	}

	fmt.Println(string(jsonEvent))
}

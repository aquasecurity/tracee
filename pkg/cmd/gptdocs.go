package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	gogpt "github.com/sashabaranov/go-gpt3"
	"gopkg.in/yaml.v2"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
)

const (
	amountOfWorkers = 20
	timeoutInSec    = 45
)

const (
	eventsTemplate  = "./docs/contributing/events/format.md"
	outputDirectory = "./dist/gptdocs"
)

type GPTDocsRunner struct {
	OpenAIKey         string
	OpenAITemperature float64
	OpenAIMaxTokens   int
	GivenEvents       []string
}

type WorkRet struct {
	eventName string
	fileName  string
	err       error
}

var once sync.Once

func (r GPTDocsRunner) Run(ctx context.Context) error {
	template, err := os.ReadFile(eventsTemplate)
	if err != nil {
		return fmt.Errorf("error reading events template: %v", err)
	}

	evtChannel := make(chan events.Definition, 1)
	retChannel := make(chan WorkRet, 1)
	wrkChannel := make(chan string, 1)

	var wg sync.WaitGroup

	// Go routines pool to handle work

	for i := 0; i < amountOfWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case evt := <-evtChannel:
					wrkChannel <- evt.GetName()
					ctxTimeout, cancel := context.WithTimeout(ctx, timeoutInSec*time.Second)
					fileName, err := r.GenerateSyscall(ctxTimeout, template, evt)
					retChannel <- WorkRet{evt.GetName(), fileName, err}
					cancel()
				}
			}
		}()
	}

	// Routine to handle work status

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case f := <-wrkChannel:
				fmt.Printf("WORKING (%v)...\n", f)
			case r := <-retChannel:
				if r.err != nil {
					fmt.Printf("ERROR (%v): %v\n", r.eventName, r.err)
				} else {
					fmt.Printf("GENERATED (%v): %v\n", r.eventName, r.fileName)
				}
			default:
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()

	// TODO: starting with syscall events only, but should also generate docs
	//       for all other events if they don't exist. Note that for the other
	//       events, the event definition should marshal everything into strings
	//       so the chatGPT is able to understand the definition in order to
	//       generate the event doc based on the template.

	// Pick all events

	var evt events.Definition

	eventDefinitions := events.Core.GetDefinitions()

	// Check if the given events exist

	for _, given := range r.GivenEvents {
		_, ok := events.Core.GetDefinitionIDByName(given)
		if !ok {
			logger.Errorw("Event definition not found", "event", given)
		}
	}

	// Run all the events map through the GPT3 API

	for _, evt = range eventDefinitions {
		if !evt.IsSyscall() {
			continue
		}

		// Check if the filename exists already and skip if it does

		fileName := outputDirectory + "/" + evt.GetName() + ".md"
		_, err := os.Stat(fileName)
		if err == nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				logger.Debugw("File already exists", "file", fileName)
				continue
			}
		}

		// Check if the event is in the given list of events and skip if it not

		if len(r.GivenEvents) > 0 {
			found := false
			for _, given := range r.GivenEvents {
				if strings.Contains(evt.GetName(), given) {
					found = true
				}
			}
			if !found {
				logger.Debugw("Event not in given list", "event", evt.GetName())
				continue
			}
		}

		logger.Debugw("Picked event", "event", evt.GetName())

		// Submit event to be processed

		select {
		case <-ctx.Done():
			return nil
		case evtChannel <- evt:
		}
	}

	wg.Wait()

	return nil
}

func (r GPTDocsRunner) GenerateSyscall(
	ctx context.Context, template []byte, evt events.Definition,
) (
	string, error,
) {
	once.Do(func() {
		if os.MkdirAll(outputDirectory, 0755) != nil {
			logger.Errorw("Error creating output directory")
		}
	})

	fileName := outputDirectory + "/" + evt.GetName() + ".md"

	_, err := os.Stat(fileName)
	if err == nil {
		return "", fmt.Errorf("file %s already exists", fileName)
	}

	// Marshal the event into JSON

	var y []byte

	y, err = yaml.Marshal(evt.GetParams())
	if err != nil {
		logger.Errorw("Error marshaling event", "err", err)
	}

	headNote := `
You are a software engineer writing a markdown file, based on a given template,
that will describe an event from a tracing software. This event comes from a
syscall being executed and has the same name, or similar, as the syscall name.
The event arguments are related to the syscall arguments. All the contents of
the markdown file should come from the linux manual page of the given syscall or
given information. The hooked function item is the kernel entry point for the
given syscall. The template for this markdown file is the following:
`
	templateYaml := fmt.Sprintf("```yaml\n%s\n```", template[:])
	eventArgsYaml := fmt.Sprintf("```yaml\n%s```", y)

	reqStr := fmt.Sprintf("%s"+ // head
		"\n%s\n\n"+ // template
		"The event, or syscall, name is \"%s\" "+
		"and the parameter names and types are:\n"+
		"\n%s\n",
		headNote, templateYaml, evt.GetName(), eventArgsYaml,
	)

	evtChannel := gogpt.NewClient(r.OpenAIKey)

	req := gogpt.CompletionRequest{
		Model:       gogpt.GPT3TextDavinci003,
		MaxTokens:   r.OpenAIMaxTokens,
		Temperature: float32(r.OpenAITemperature),
		Prompt:      reqStr,
	}

	stream, err := evtChannel.CreateCompletionStream(ctx, req)
	if err != nil {
		return "", fmt.Errorf("error creating completion stream: %v", err)
	}
	defer stream.Close()

	choices := []string{}
	for {
		response, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("error receiving completion stream: %v", err)
		}

		for _, c := range response.Choices {
			choices = append(choices, c.Text)
		}
	}

	choicesStr := strings.Join(choices, "")

	if len(choicesStr) <= 10 {
		return fileName, fmt.Errorf("no output from OpenAI")
	}

	footNote := `
> This document was automatically generated by OpenAI and needs review. It might
> not be accurate and might contain errors. The authors of Tracee recommend that
> the user reads the "events.go" source file to understand the events and their
> arguments better.
`

	outputFile, err := os.OpenFile(fileName, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return "", fmt.Errorf("error opening output file: %v", err)
	}
	defer func() {
		if err := outputFile.Close(); err != nil {
			logger.Errorw("Closing file", "error", err)
		}
	}()

	_, err = fmt.Fprintf(outputFile, "%v\n%v", choicesStr, footNote)

	return fileName, err
}

// TODO: generate docs for all other events if they don't exist:
//
// - Security events
// - Cgroup events
// - NetPacket events
// ...
//
// NOTE: Use eBPF function snippet to automate documentation for those.
//       It is a bit different than the syscall events (simpler).
//

/*

For future reference:

probeHandles, err := probes.Init(nil, true)

and then:

func (r GPTDocsRunner) GenerateXXX(
	ctx context.Context, template []byte, evt events.Event, probeHandles probes.Probes,
) error {

	// To each event, pick info about needed probes

	var info []handleInfo

	for _, p := range evt.Probes {
		evtName, progName := probeHandles.GetEventName(p.Handle)
		hInfo := handleInfo{
			eventName:   evtName,
			programName: progName,
		}
		info = append(info, hInfo)
	}

	return nil
}

or something similar.

*/

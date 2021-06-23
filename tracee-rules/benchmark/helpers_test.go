package benchmark

import (
	_ "embed"
	"encoding/gob"
	"fmt"
	"io"
	"math/rand"
	"os"
	"testing"

	tracee "github.com/aquasecurity/tracee/tracee-ebpf/tracee/external"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

var (
	innocentEvent = tracee.Event{
		EventName: "innocent",
		Args: []tracee.Argument{
			{
				ArgMeta: tracee.ArgMeta{
					Name: "foo",
				},
				Value: "bar",
			},
		},
	}

	triggerCodeInjectorPtraceEvent = tracee.Event{
		EventName: "ptrace",
		Args: []tracee.Argument{
			{
				ArgMeta: tracee.ArgMeta{
					Name: "request",
				},
				Value: "PTRACE_POKETEXT",
			},
		},
	}
	triggerCodeInjectorOpenEvent = tracee.Event{
		EventName: "open",
		Args: []tracee.Argument{
			{
				ArgMeta: tracee.ArgMeta{
					Name: "flags",
				},
				Value: "o_wronly",
			},
			{
				ArgMeta: tracee.ArgMeta{
					Name: "pathname",
				},
				Value: "/proc/self/mem",
			},
		},
	}
	triggerAntiDebuggingEvent = tracee.Event{
		EventName: "ptrace",
		Args: []tracee.Argument{
			{
				ArgMeta: tracee.ArgMeta{
					Name: "request",
				},
				Value: "PTRACE_TRACEME",
			},
		},
	}
)

func ProduceEventsInMemory(eventsCh chan<- types.Event, n int) {
	ProduceEventsInMemoryRandom(eventsCh, n, []tracee.Event{
		innocentEvent,
		innocentEvent,
		innocentEvent,
		triggerCodeInjectorPtraceEvent,
		triggerCodeInjectorOpenEvent,
		triggerAntiDebuggingEvent,
	}...)
}

func ProduceEventsInMemoryRandom(eventsCh chan<- types.Event, n int, seed ...tracee.Event) {
	for i := 0; i < n; i++ {
		s := rand.Intn(len(seed))
		eventsCh <- seed[s]
	}
}

func ProduceEventsFromGobFile(t *testing.T, eventsCh chan<- types.Event, path string) error {
	inputFile, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening file: %v", err)
	}
	defer inputFile.Close()

	dec := gob.NewDecoder(inputFile)
	gob.Register(tracee.Event{})
	gob.Register(tracee.SlimCred{})

	for {
		var event tracee.Event
		err := dec.Decode(&event)
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return fmt.Errorf("decoding event: %v", err)
			}
		} else {
			eventsCh <- event
		}
	}
	return nil
}

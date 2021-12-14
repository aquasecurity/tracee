package benchmark

import (
	_ "embed"

	"encoding/gob"
	"fmt"
	"io"
	"math/rand"
	"os"

	"github.com/aquasecurity/tracee/pkg/external"
	"github.com/aquasecurity/tracee/tracee-rules/engine"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

var (
	innocentEvent = external.Event{
		Timestamp:           7126141189,
		ProcessID:           1,
		ThreadID:            1,
		ParentProcessID:     4798,
		HostProcessID:       4819,
		HostThreadID:        4819,
		HostParentProcessID: 4798,
		UserID:              0,
		MountNS:             4026532256,
		PIDNS:               4026532259,
		ProcessName:         "cadvisor",
		HostName:            "4213291591ab",
		EventID:             257,
		EventName:           "openat",
		ArgsNum:             4,
		ReturnValue:         14,
		Args: []external.Argument{
			{
				ArgMeta: external.ArgMeta{
					Name: "dirfd",
					Type: "int",
				},
				Value: -100,
			},
			{
				ArgMeta: external.ArgMeta{
					Name: "pathname",
					Type: "const char",
				},
				Value: "/sys/fs/cgroup/cpu,cpuacct/cpuacct.stat",
			},
			{
				ArgMeta: external.ArgMeta{
					Name: "flags",
					Type: "int",
				},
				Value: "O_RDONLY|O_CLOEXEC",
			},
			{
				ArgMeta: external.ArgMeta{
					Name: "mode",
					Type: "mode_t",
				},
				Value: 5038682,
			},
		},
	}

	triggerCodeInjectorPtraceEvent = external.Event{
		Timestamp:           6123321183,
		ProcessID:           1,
		ThreadID:            1,
		ParentProcessID:     3788,
		HostProcessID:       3217,
		HostThreadID:        3217,
		HostParentProcessID: 3788,
		UserID:              0,
		MountNS:             2983424533,
		PIDNS:               2983424536,
		ProcessName:         "injector",
		HostName:            "234134134ab",
		EventID:             328,
		EventName:           "ptrace",
		ArgsNum:             2,
		ReturnValue:         0,
		Args: []external.Argument{
			{
				ArgMeta: external.ArgMeta{
					Name: "request",
				},
				Value: "PTRACE_POKETEXT",
			},
		},
	}
	triggerCodeInjectorOpenEvent = external.Event{
		Timestamp:           5123321532,
		ProcessID:           1,
		ThreadID:            1,
		ParentProcessID:     3788,
		HostProcessID:       3217,
		HostThreadID:        3217,
		HostParentProcessID: 3788,
		UserID:              0,
		MountNS:             2983424533,
		PIDNS:               2983424536,
		ProcessName:         "injector",
		HostName:            "234134134ab",
		EventID:             477,
		EventName:           "open",
		ArgsNum:             2,
		ReturnValue:         0,
		Args: []external.Argument{
			{
				ArgMeta: external.ArgMeta{
					Name: "flags",
				},
				Value: "o_wronly",
			},
			{
				ArgMeta: external.ArgMeta{
					Name: "pathname",
				},
				Value: "/proc/self/mem",
			},
		},
	}

	triggerAntiDebuggingEvent = external.Event{
		Timestamp:           5323321532,
		ProcessID:           1,
		ThreadID:            1,
		ParentProcessID:     3788,
		HostProcessID:       3217,
		HostThreadID:        3217,
		HostParentProcessID: 3788,
		UserID:              0,
		MountNS:             2983424533,
		PIDNS:               2983424536,
		ProcessName:         "malware",
		HostName:            "234134134ab",
		EventID:             521,
		EventName:           "ptrace",
		ArgsNum:             2,
		ReturnValue:         124,
		Args: []external.Argument{
			{
				ArgMeta: external.ArgMeta{
					Name: "request",
				},
				Value: "PTRACE_TRACEME",
			},
		},
	}
)

func ProduceEventsInMemory(n int) engine.EventSources {
	return ProduceEventsInMemoryRandom(n, []external.Event{
		innocentEvent,
		innocentEvent,
		innocentEvent,
		triggerCodeInjectorPtraceEvent,
		triggerCodeInjectorOpenEvent,
		triggerAntiDebuggingEvent,
	}...)
}

func ProduceEventsInMemoryRandom(n int, seed ...external.Event) engine.EventSources {
	eventsCh := make(chan types.Event, n)

	for i := 0; i < n; i++ {
		s := rand.Intn(len(seed))
		eventsCh <- seed[s]
	}

	close(eventsCh)
	return engine.EventSources{
		Tracee: eventsCh,
	}
}

func ProduceEventsFromGobFile(n int, path string) (engine.EventSources, error) {
	inputFile, err := os.Open(path)
	if err != nil {
		return engine.EventSources{}, fmt.Errorf("opening file: %v", err)
	}
	defer inputFile.Close()

	dec := gob.NewDecoder(inputFile)
	gob.Register(external.Event{})
	gob.Register(external.SlimCred{})
	gob.Register(make(map[string]string))

	eventsCh := make(chan types.Event, n)

	for {
		var event external.Event
		err := dec.Decode(&event)
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return engine.EventSources{}, fmt.Errorf("decoding event: %v", err)
			}
		} else {
			eventsCh <- event
		}
	}

	close(eventsCh)
	return engine.EventSources{
		Tracee: eventsCh,
	}, nil
}

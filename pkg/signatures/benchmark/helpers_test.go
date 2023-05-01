package benchmark

import (
	_ "embed"
	"encoding/gob"
	"fmt"
	"io"
	"math/rand"
	"os"

	"github.com/aquasecurity/tracee/pkg/signatures/engine"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

var (
	innocentEvent = trace.Event{
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
		Args: []trace.Argument{
			{
				ArgMeta: trace.ArgMeta{
					Name: "dirfd",
					Type: "int",
				},
				Value: -100,
			},
			{
				ArgMeta: trace.ArgMeta{
					Name: "pathname",
					Type: "const char",
				},
				Value: "/sys/fs/cgroup/cpu,cpuacct/cpuacct.stat",
			},
			{
				ArgMeta: trace.ArgMeta{
					Name: "flags",
					Type: "int",
				},
				Value: "O_RDONLY|O_CLOEXEC",
			},
			{
				ArgMeta: trace.ArgMeta{
					Name: "mode",
					Type: "mode_t",
				},
				Value: 5038682,
			},
		},
	}

	triggerCodeInjectorPtraceEvent = trace.Event{
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
		Args: []trace.Argument{
			{
				ArgMeta: trace.ArgMeta{
					Name: "request",
				},
				Value: "PTRACE_POKETEXT",
			},
		},
	}
	triggerCodeInjectorOpenEvent = trace.Event{
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
		Args: []trace.Argument{
			{
				ArgMeta: trace.ArgMeta{
					Name: "flags",
				},
				Value: "o_wronly",
			},
			{
				ArgMeta: trace.ArgMeta{
					Name: "pathname",
				},
				Value: "/proc/self/mem",
			},
		},
	}

	triggerAntiDebuggingEvent = trace.Event{
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
		Args: []trace.Argument{
			{
				ArgMeta: trace.ArgMeta{
					Name: "request",
				},
				Value: "PTRACE_TRACEME",
			},
		},
	}
)

func ProduceEventsInMemory(n int) engine.EventSources {
	return ProduceEventsInMemoryRandom(n, []trace.Event{
		innocentEvent,
		innocentEvent,
		innocentEvent,
		triggerCodeInjectorPtraceEvent,
		triggerCodeInjectorOpenEvent,
		triggerAntiDebuggingEvent,
	}...)
}

func ProduceEventsInMemoryRandom(n int, seed ...trace.Event) engine.EventSources {
	eventsCh := make(chan protocol.Event, n)

	for i := 0; i < n; i++ {
		s := rand.Intn(len(seed))
		e := seed[s].ToProtocol()
		eventsCh <- e
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
	gob.Register(trace.Event{})
	gob.Register(trace.SlimCred{})
	gob.Register(make(map[string]string))

	eventsCh := make(chan protocol.Event, n)

	for {
		var event trace.Event
		err := dec.Decode(&event)
		if err != nil {
			if err != io.EOF {
				return engine.EventSources{}, fmt.Errorf("decoding event: %v", err)
			}
			break
		}
		e := event.ToProtocol()
		eventsCh <- e
	}

	close(eventsCh)
	return engine.EventSources{
		Tracee: eventsCh,
	}, nil
}

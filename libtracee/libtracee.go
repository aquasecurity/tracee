package libtracee

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/aquasecurity/tracee/tracee-ebpf/tracee"
	"github.com/aquasecurity/tracee/tracee-ebpf/tracee/external"

	"github.com/aquasecurity/tracee/tracee-rules/engine"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

func SetupTracee(sigs []types.Signature, inputEventsCount int) (*int, string) {
	traceeEventsChan, traceeRulesInputChan, totalEvents, done, trcE, tmpDir, err := setupTraceeBPF(inputEventsCount)
	fmt.Println("tracee tmpDir: ", tmpDir)

	go func() {
		eventForwarder(traceeEventsChan, traceeRulesInputChan, &totalEvents)
	}()

	output := make(chan types.Finding, inputEventsCount)
	e, err := engine.NewEngine(sigs, engine.EventSources{Tracee: traceeRulesInputChan}, output, os.Stderr)
	if err != nil {
		panic(err)
	}

	go func() {
		fmt.Println("starting tracee-ebpf...")
		err = trcE.Run()
		if err != nil {
			panic(err)
		}
	}()

	go func() {
		fmt.Println("starting tracee-rules....")
		e.Start(done)
	}()
	return &totalEvents, tmpDir
}

func AddNSigs(sigFuncs []func() (types.Signature, error)) []types.Signature {
	var sigs []types.Signature
	for _, sf := range sigFuncs {
		s, err := sf()
		if err != nil {
			panic(err)
		}
		sigs = append(sigs, s)
	}
	return sigs
}

func setupTraceeBPF(inputEventsCount int) (chan external.Event, chan types.Event, int, chan bool, *tracee.Tracee, string, error) {
	// channel for tracee ebpf to send events to
	traceeEventsChan := make(chan external.Event, inputEventsCount)
	traceeRulesInputChan := make(chan types.Event, inputEventsCount)
	var totalEvents int
	done := make(chan bool, 1)

	tmpDir, _ := ioutil.TempDir("", "Benchmark_Tracee-*")

	eventsToTrace := []int32{122, 268, 6, 57, 165, 292, 106, 157, 269, 59, 92, 49, 217, 310, 1006, 87, 133, 429, 50, 259, 329, 113, 123, 175, 439, 319, 94, 313, 2, 5, 78, 32, 3, 105, 114, 42, 56, 435, 62, 101, 90, 166, 260, 257, 43, 51, 322, 176, 266, 1022, 321, 85, 41, 311, 4, 21, 1004, 1016, 91, 437, 436, 93, 1015, 263, 58, 33, 1014, 88, 288}

	trcE, err := tracee.New(tracee.Config{
		Filter: &tracee.Filter{
			UIDFilter:     &tracee.UintFilter{},
			PIDFilter:     &tracee.UintFilter{},
			MntNSFilter:   &tracee.UintFilter{},
			PidNSFilter:   &tracee.UintFilter{},
			CommFilter:    &tracee.StringFilter{},
			UTSFilter:     &tracee.StringFilter{},
			ContFilter:    &tracee.BoolFilter{},
			NewContFilter: &tracee.BoolFilter{},
			ArgFilter:     &tracee.ArgFilter{},
			RetFilter:     &tracee.RetFilter{},
			NewPidFilter:  &tracee.BoolFilter{},
			EventsToTrace: eventsToTrace,
		},
		Capture:            &tracee.CaptureConfig{OutputPath: tmpDir},
		ChanEvents:         traceeEventsChan,
		BPFObjPath:         "tracee.bpf.5_8_0-55-generic.v0_5_4-18-g31f21b8.o",
		Output:             &tracee.OutputConfig{Format: "table"},
		PerfBufferSize:     1024,
		BlobPerfBufferSize: 1024,
	})
	if err != nil {
		panic(err)
	}
	return traceeEventsChan, traceeRulesInputChan, totalEvents, done, trcE, tmpDir, err
}

// Event forwarder from tracee-ebpf to tracee-rules
func eventForwarder(traceeEventsChan chan external.Event, traceeRulesInputChan chan types.Event, totalEvents *int) {
	for {
		select {
		case event := <-traceeEventsChan:
			//fmt.Println(event)
			traceeRulesInputChan <- event // TODO: We need to use same channel types for tracee-ebpf output and tracee-rules input
			*totalEvents += 1
		}
	}
}

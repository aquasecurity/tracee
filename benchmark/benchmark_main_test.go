package benchmark

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"testing"

	"github.com/aquasecurity/tracee/tracee-rules/benchmark/signature/golang"
	"github.com/aquasecurity/tracee/tracee-rules/benchmark/signature/rego"

	"github.com/aquasecurity/tracee/tracee-rules/benchmark/signature/wasm"

	"github.com/aquasecurity/tracee/tracee-ebpf/tracee/external"

	"github.com/aquasecurity/tracee/tracee-ebpf/tracee"
	"github.com/aquasecurity/tracee/tracee-rules/engine"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

const (
	inputEventsCount = 10000
)

type bench struct {
	name    string
	numSigs []int
	sigFunc func() (types.Signature, error)
}

func BenchmarkTracee(b *testing.B) {
	benches := []bench{
		{
			name:    "golang sigs only",
			numSigs: []int{1, 2, 4, 8},
			sigFunc: golang.NewCodeInjectionSignature,
		},
		{
			name:    "rego sigs only",
			numSigs: []int{1, 2, 4},
			sigFunc: rego.NewCodeInjectionSignature,
		},
		{
			name:    "wasm sigs only",
			numSigs: []int{1, 2},
			sigFunc: wasm.NewCodeInjectionSignature,
		},
	}

	for _, bc := range benches {
		bc := bc
		for _, sigs := range bc.numSigs {
			for i := 0; i < b.N; i++ {
				b.Run(fmt.Sprintf("%s/%dsigs", bc.name, sigs), func(b *testing.B) {
					b.ReportAllocs()
					b.StopTimer()
					totalEvents, tmpDir := setupBench(sigs, bc)
					defer func() {
						_ = os.RemoveAll(tmpDir)
					}()
					b.StartTimer()

					sig := make(chan os.Signal, 1)
					signal.Notify(sig, os.Interrupt)
					go func() {
						generateAndStop(totalEvents, sig)
					}()

					fmt.Println("waiting for interrupt to finish...")
					<-sig
					fmt.Println("total events: ", *totalEvents)
				})
			}

		}
	}
}

func setupBench(numSigs int, bc bench) (*int, string) {
	traceeEventsChan, traceeRulesInputChan, totalEvents, done, trcE, tmpDir, err := setupTraceeBPF()
	fmt.Println(tmpDir)

	go func() {
		eventForwarder(traceeEventsChan, traceeRulesInputChan, &totalEvents)
	}()

	output := make(chan types.Finding, inputEventsCount)
	e, err := engine.NewEngine(addNSigs(numSigs, bc.sigFunc), engine.EventSources{Tracee: traceeRulesInputChan}, output, os.Stderr)
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

func generateAndStop(totalEvents *int, sig chan os.Signal) {
	for {
		if *totalEvents >= inputEventsCount {
			sig <- os.Interrupt
		} else {
			_ = exec.Command("ls").Run()
		}
	}
}

func setupTraceeBPF() (chan external.Event, chan types.Event, int, chan bool, *tracee.Tracee, string, error) {
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

func addNSigs(numSigs int, sigFunc func() (types.Signature, error)) []types.Signature {
	var sigs []types.Signature
	for i := 0; i < numSigs; i++ {
		s, err := sigFunc()
		if err != nil {
			panic(err)
		}
		sigs = append(sigs, s)
	}
	return sigs
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

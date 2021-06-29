package benchmark

import (
	"os"
	"testing"
	"time"

	"github.com/aquasecurity/tracee/tracee-rules/engine"

	"github.com/aquasecurity/tracee/tracee-rules/benchmark/signature/golang"
	"github.com/aquasecurity/tracee/tracee-rules/benchmark/signature/rego"
	"github.com/aquasecurity/tracee/tracee-rules/benchmark/signature/wasm"
	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/stretchr/testify/require"
)

const (
	inputEventsCount = 1000
)

func BenchmarkOnEventCodeInjectionRule(b *testing.B) {
	benches := []struct {
		name    string
		sigFunc func() (types.Signature, error)
	}{
		{
			name:    "rego",
			sigFunc: rego.NewCodeInjectionSignature,
		},
		{
			name:    "golang",
			sigFunc: golang.NewCodeInjectionSignature,
		},
		{
			name:    "wasm",
			sigFunc: wasm.NewCodeInjectionSignature,
		},
	}

	for _, bc := range benches {
		b.Run(bc.name, func(b *testing.B) {
			s, err := bc.sigFunc()
			require.NoError(b, err, bc.name)
			require.NoError(b, s.Init(ignoreFinding), bc.name)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				require.NoError(b, s.OnEvent(triggerCodeInjectorPtraceEvent), bc.name)
			}
		})
	}
}

func BenchmarkEngineWithCodeInjection(b *testing.B) {
	benches := []struct {
		name    string
		sigFunc func() (types.Signature, error)
	}{
		{
			name:    "rego",
			sigFunc: rego.NewCodeInjectionSignature,
		},
		{
			name:    "golang",
			sigFunc: golang.NewCodeInjectionSignature,
		},
		{
			name:    "wasm",
			sigFunc: wasm.NewCodeInjectionSignature,
		},
	}

	for _, bc := range benches {
		b.Run(bc.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Produce events without timing it
				b.StopTimer()
				eventsCh := make(chan types.Event, inputEventsCount)
				inputs := ProduceEventsInMemory(inputEventsCount)
				output := make(chan types.Finding, inputEventsCount)

				s, err := bc.sigFunc()
				require.NoError(b, err, bc.name)

				e := engine.NewEngine([]types.Signature{s}, inputs, output, os.Stderr)
				b.StartTimer()

				// Start rules engine and wait until all events are processed
				e.Start(waitForEventsProcessed(eventsCh))

				b.Logf("Test is done with %d findings", len(output))
			}
		})
	}
}

func BenchmarkEngineWithMultipleRules(b *testing.B) {
	benches := []struct {
		name     string
		sigFuncs []func() (types.Signature, error)
	}{
		{
			name:     "rego and golang",
			sigFuncs: []func() (types.Signature, error){rego.NewCodeInjectionSignature, golang.NewCodeInjectionSignature},
		},
		{
			name:     "wasm and golang",
			sigFuncs: []func() (types.Signature, error){wasm.NewCodeInjectionSignature, golang.NewCodeInjectionSignature},
		},
		{
			name:     "rego and wasm",
			sigFuncs: []func() (types.Signature, error){rego.NewCodeInjectionSignature, wasm.NewCodeInjectionSignature},
		},
		{
			name:     "rego and golang and wasm",
			sigFuncs: []func() (types.Signature, error){rego.NewCodeInjectionSignature, golang.NewCodeInjectionSignature, wasm.NewCodeInjectionSignature},
		},
	}

	for _, bc := range benches {
		b.Run(bc.name, func(b *testing.B) {
			var sigs []types.Signature
			for _, sig := range bc.sigFuncs {
				s, _ := sig()
				sigs = append(sigs, s)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Produce events without timing it
				b.StopTimer()
				eventsCh := make(chan types.Event, inputEventsCount)
				inputs := ProduceEventsInMemory(inputEventsCount)
				output := make(chan types.Finding, inputEventsCount*len(sigs))

				e := engine.NewEngine(sigs, inputs, output, os.Stderr)
				b.StartTimer()

				// Start rules engine and wait until all events are processed
				e.Start(waitForEventsProcessed(eventsCh))

				b.Logf("Test is done with %d findings", len(output))
			}
		})
	}
}

func waitForEventsProcessed(eventsCh chan types.Event) chan bool {
	done := make(chan bool, 1)
	go func() {
		for {
			if len(eventsCh) == 0 {
				done <- true
				return
			}
			time.Sleep(1 * time.Millisecond)
		}
	}()
	return done
}

func ignoreFinding(_ types.Finding) {
	// noop
}

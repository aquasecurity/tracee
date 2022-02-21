package benchmark

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/aquasecurity/tracee/pkg/rules/benchmark/signature/golang"
	"github.com/aquasecurity/tracee/pkg/rules/benchmark/signature/rego"
	"github.com/aquasecurity/tracee/pkg/rules/benchmark/signature/wasm"
	"github.com/aquasecurity/tracee/pkg/rules/engine"
	"github.com/aquasecurity/tracee/types"
	"github.com/stretchr/testify/require"
)

const (
	inputEventsCount = 1000
)

func BenchmarkOnEventWithCodeInjectionSignature(b *testing.B) {
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

func BenchmarkEngineWithCodeInjectionSignature(b *testing.B) {
	benches := []struct {
		name           string
		sigFunc        func() (types.Signature, error)
		preparedEvents bool
	}{
		{
			name:    "rego",
			sigFunc: rego.NewCodeInjectionSignature,
		},
		{
			name:           "rego + prepared events",
			sigFunc:        rego.NewCodeInjectionSignature,
			preparedEvents: true,
		},
		{
			name:    "golang",
			sigFunc: golang.NewCodeInjectionSignature,
		},
		{
			name:           "golang + prepared events",
			sigFunc:        golang.NewCodeInjectionSignature,
			preparedEvents: true,
		},
		{
			name:    "wasm",
			sigFunc: wasm.NewCodeInjectionSignature,
		},
		{
			name:           "wasm + prepared events",
			sigFunc:        wasm.NewCodeInjectionSignature,
			preparedEvents: true,
		},
	}

	for _, bc := range benches {
		b.Run(bc.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Produce events without timing it
				b.StopTimer()
				inputs := ProduceEventsInMemory(inputEventsCount)
				output := make(chan types.Finding, inputEventsCount)

				s, err := bc.sigFunc()
				require.NoError(b, err, bc.name)

				e, err := engine.NewEngine([]types.Signature{s}, inputs, output, os.Stderr, engine.Config{
					ParsedEvents: bc.preparedEvents,
				})
				require.NoError(b, err, "constructing engine")
				b.StartTimer()

				// Start rules engine and wait until all events are processed
				e.Start(waitForEventsProcessed(inputs.Tracee))
			}
		})
	}
}

func BenchmarkEngineWithMultipleSignatures(b *testing.B) {
	benches := []struct {
		name           string
		sigFuncs       []func() (types.Signature, error)
		preparedEvents bool
	}{
		{
			name:     "rego and golang",
			sigFuncs: []func() (types.Signature, error){rego.NewCodeInjectionSignature, golang.NewCodeInjectionSignature},
		},
		{
			name:           "rego and golang, with prepared events",
			sigFuncs:       []func() (types.Signature, error){rego.NewCodeInjectionSignature, golang.NewCodeInjectionSignature},
			preparedEvents: true,
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
				inputs := ProduceEventsInMemory(inputEventsCount)
				output := make(chan types.Finding, inputEventsCount*len(sigs))

				e, err := engine.NewEngine(sigs, inputs, output, os.Stderr, engine.Config{
					ParsedEvents: bc.preparedEvents,
				})
				require.NoError(b, err, "constructing engine")
				b.StartTimer()

				// Start rules engine and wait until all events are processed
				e.Start(waitForEventsProcessed(inputs.Tracee))
			}
		})
	}
}

func BenchmarkEngineWithNSignatures(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping in short mode")
	}

	benches := []struct {
		name     string
		sigFunc  func() (types.Signature, error)
		sigCount []int
	}{
		{
			name:     "noop",
			sigFunc:  golang.NewNoopSignature,
			sigCount: []int{2, 4, 8, 16, 32, 64, 128},
		},
		{
			name:     "rego",
			sigFunc:  rego.NewCodeInjectionSignature,
			sigCount: []int{2, 4, 8, 16, 32, 64, 128},
		},
		{
			name:     "golang",
			sigFunc:  golang.NewCodeInjectionSignature,
			sigCount: []int{2, 4, 8, 16, 32, 64, 128},
		},
		{
			name:    "wasm",
			sigFunc: wasm.NewCodeInjectionSignature,
			// This takes time ...
			sigCount: []int{2, 4, 8, 16, 32, 64, 128},
		},
	}

	for _, bc := range benches {
		for _, tc := range bc.sigCount {
			b.Run(fmt.Sprintf("%s/%dSignatures", bc.name, tc), func(b *testing.B) {
				sigs := make([]types.Signature, tc)
				for i := range sigs {
					sig, err := bc.sigFunc()
					require.NoError(b, err, "constructing signature")
					sigs[i] = sig
				}

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					// Produce events without timing it
					b.StopTimer()
					inputs := ProduceEventsInMemory(inputEventsCount)
					output := make(chan types.Finding, inputEventsCount*len(sigs))
					e, err := engine.NewEngine(sigs, inputs, output, os.Stderr, engine.Config{})
					require.NoError(b, err, "constructing engine")
					b.StartTimer()

					// Start rules engine and wait until all events are processed
					e.Start(waitForEventsProcessed(inputs.Tracee))
				}
			})
		}
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

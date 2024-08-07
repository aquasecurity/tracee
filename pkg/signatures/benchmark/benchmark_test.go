package benchmark

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/signatures/benchmark/signature/golang"
	"github.com/aquasecurity/tracee/pkg/signatures/benchmark/signature/rego"
	"github.com/aquasecurity/tracee/pkg/signatures/engine"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
)

const (
	inputEventsCount = 1000
)

func BenchmarkOnEventWithCodeInjectionSignature(b *testing.B) {
	benches := []struct {
		name    string
		sigFunc func() (detect.Signature, error)
	}{
		{
			name:    "rego",
			sigFunc: rego.NewCodeInjectionSignature,
		},
		{
			name:    "golang",
			sigFunc: golang.NewCodeInjectionSignature,
		},
	}

	for _, bc := range benches {
		b.Run(bc.name, func(b *testing.B) {
			s, err := bc.sigFunc()
			require.NoError(b, err, bc.name)
			require.NoError(b, s.Init(detect.SignatureContext{Callback: ignoreFinding}), bc.name)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				event := triggerCodeInjectorPtraceEvent.ToProtocol()
				require.NoError(b, s.OnEvent(event), bc.name)
			}
		})
	}
}

func BenchmarkEngineWithCodeInjectionSignature(b *testing.B) {
	benches := []struct {
		name           string
		sigFunc        func() (detect.Signature, error)
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
	}

	for _, bc := range benches {
		b.Run(bc.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Produce events without timing it
				b.StopTimer()
				inputs := ProduceEventsInMemory(inputEventsCount)
				output := make(chan *detect.Finding, inputEventsCount)

				s, err := bc.sigFunc()
				require.NoError(b, err, bc.name)

				config := engine.Config{
					Signatures: []detect.Signature{s},
				}

				e, err := engine.NewEngine(config, inputs, output)
				require.NoError(b, err, "constructing engine")

				err = e.Init()
				require.NoError(b, err, "initializing engine")
				b.StartTimer()

				// Start signatures engine and wait until all events are processed
				e.Start(waitForEventsProcessed(inputs.Tracee))

				// Set engine to nil to help with garbage collection
				e = nil
				runtime.GC()
			}
		})
	}
}

func BenchmarkEngineWithMultipleSignatures(b *testing.B) {
	benches := []struct {
		name           string
		sigFuncs       []func() (detect.Signature, error)
		preparedEvents bool
	}{
		{
			name:     "rego and golang",
			sigFuncs: []func() (detect.Signature, error){rego.NewCodeInjectionSignature, golang.NewCodeInjectionSignature},
		},
		{
			name:           "rego and golang, with prepared events",
			sigFuncs:       []func() (detect.Signature, error){rego.NewCodeInjectionSignature, golang.NewCodeInjectionSignature},
			preparedEvents: true,
		},
	}

	for _, bc := range benches {
		b.Run(bc.name, func(b *testing.B) {
			var sigs []detect.Signature
			for _, sig := range bc.sigFuncs {
				s, _ := sig()
				sigs = append(sigs, s)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Produce events without timing it
				b.StopTimer()
				inputs := ProduceEventsInMemory(inputEventsCount)
				output := make(chan *detect.Finding, inputEventsCount*len(sigs))

				config := engine.Config{
					Signatures: sigs,
				}
				e, err := engine.NewEngine(config, inputs, output)
				require.NoError(b, err, "constructing engine")

				err = e.Init()
				require.NoError(b, err, "initializing engine")
				b.StartTimer()

				// Start signatures engine and wait until all events are processed
				e.Start(waitForEventsProcessed(inputs.Tracee))

				// Set engine to nil to help with garbage collection
				e = nil
				runtime.GC()
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
		sigFunc  func() (detect.Signature, error)
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
	}

	for _, bc := range benches {
		for _, tc := range bc.sigCount {
			b.Run(fmt.Sprintf("%s/%dSignatures", bc.name, tc), func(b *testing.B) {
				sigs := make([]detect.Signature, tc)
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
					output := make(chan *detect.Finding, inputEventsCount*len(sigs))

					config := engine.Config{
						Signatures: sigs,
					}

					e, err := engine.NewEngine(config, inputs, output)
					require.NoError(b, err, "constructing engine")

					err = e.Init()
					require.NoError(b, err, "initializing engine")
					b.StartTimer()

					// Start signatures engine and wait until all events are processed
					e.Start(waitForEventsProcessed(inputs.Tracee))

					// Set engine to nil to help with garbage collection
					e = nil
					runtime.GC()
				}
			})
		}
	}
}

func BenchmarkEngineMultipleMethodsGetMetadata(b *testing.B) {
	benches := []struct {
		name     string
		sigFuncs []func() (detect.Signature, error)
		Enabled  bool
	}{
		{
			name:     "Performance sig GetMetadata() - static",
			sigFuncs: []func() (detect.Signature, error){golang.NewPerformanceStatic},
		},
	}

	for _, bc := range benches {
		b.Run(bc.name, func(b *testing.B) {
			var sigs []detect.Signature
			for _, sig := range bc.sigFuncs {
				s, _ := sig()
				sigs = append(sigs, s)
			}

			for i := 0; i < b.N; i++ {
				// Produce events without timing it
				b.StopTimer()
				inputs := ProduceEventsInMemory(inputEventsCount)
				output := make(chan *detect.Finding, inputEventsCount*len(sigs))

				config := engine.Config{
					Signatures:          sigs,
					Enabled:             true,
					SigNameToEventID:    allocateEventIdsForSigs(events.StartSignatureID, sigs),
					ShouldDispatchEvent: func(int32) bool { return true },
				}

				e, err := engine.NewEngine(config, inputs, output)
				require.NoError(b, err, "constructing engine")

				err = e.Init()
				require.NoError(b, err, "initializing engine")
				b.StartTimer()

				// Start signatures engine and wait until all events are processed
				e.Start(waitForEventsProcessed(inputs.Tracee))

				b.StopTimer()

				// Set engine to nil to help with garbage collection
				e = nil
				runtime.GC()
			}
		})
	}
}
func waitForEventsProcessed(eventsCh chan protocol.Event) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			if len(eventsCh) == 0 {
				cancel()
				return
			}
			time.Sleep(1 * time.Millisecond)
		}
	}()
	return ctx
}

func ignoreFinding(_ *detect.Finding) {
	// noop
}

package benchmark

import (
	"os"
	"testing"
	"time"

	"github.com/aquasecurity/tracee/tracee-rules/benchmark/signature/golang"
	"github.com/aquasecurity/tracee/tracee-rules/benchmark/signature/rego"
	"github.com/aquasecurity/tracee/tracee-rules/engine"
	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/stretchr/testify/require"
)

const (
	inputEventsCount = 1000
)

func BenchmarkOnEventCodeInjectionRegoRule(b *testing.B) {
	codeInjectSig, err := rego.NewCodeInjectionSignature()
	require.NoError(b, err)

	err = codeInjectSig.Init(ignoreFinding)
	require.NoError(b, err)

	for i := 0; i < b.N; i++ {
		err = codeInjectSig.OnEvent(triggerCodeInjectorPtraceEvent)
		require.NoError(b, err)
	}
}

func BenchmarkOnEventCodeInjectionGoRule(b *testing.B) {
	codeInjectSig := golang.NewCodeInjectionSignature()
	err := codeInjectSig.Init(ignoreFinding)
	require.NoError(b, err)

	for i := 0; i < b.N; i++ {
		err := codeInjectSig.OnEvent(triggerCodeInjectorPtraceEvent)
		require.NoError(b, err)
	}
}

func BenchmarkEngineWithCodeInjectionRegoRule(b *testing.B) {
	// Prepare signatures
	codeInjectSig, err := rego.NewCodeInjectionSignature()
	require.NoError(b, err)

	sigs := []types.Signature{
		codeInjectSig,
	}

	for i := 0; i < b.N; i++ {
		// Produce events
		eventsCh := make(chan types.Event, inputEventsCount)
		ProduceEventsInMemory(eventsCh, inputEventsCount)

		inputs := engine.EventSources{
			Tracee: eventsCh,
		}
		output := make(chan types.Finding, inputEventsCount)

		e := engine.NewEngine(sigs, inputs, output, os.Stderr)
		// Start rules engine and wait until all events are processed
		e.Start(waitForEventsProcessed(eventsCh))

		b.Logf("Test is done with %d findings", len(output))
	}
}

func BenchmarkEngineWithCodeInjectionGoRule(b *testing.B) {
	// Prepare signatures
	codeInjectSig := golang.NewCodeInjectionSignature()

	sigs := []types.Signature{
		codeInjectSig,
	}

	for i := 0; i < b.N; i++ {
		// Produce events
		eventsCh := make(chan types.Event, inputEventsCount)
		ProduceEventsInMemory(eventsCh, inputEventsCount)

		inputs := engine.EventSources{
			Tracee: eventsCh,
		}
		output := make(chan types.Finding, inputEventsCount)

		e := engine.NewEngine(sigs, inputs, output, os.Stderr)
		// Start rules engine and wait until all events are processed
		e.Start(waitForEventsProcessed(eventsCh))

		b.Logf("Test is done with %d findings", len(output))
	}
}

func BenchmarkEngineWithMultipleRegoAndGoRules(b *testing.B) {
	// Prepare signatures
	codeInjectionRegoSig, _ := rego.NewCodeInjectionSignature()
	antiDebuggingRegoSig, _ := rego.NewAntiDebuggingSignature()

	sigs := []types.Signature{
		codeInjectionRegoSig,
		antiDebuggingRegoSig,

		golang.NewCodeInjectionSignature(),
		golang.NewAntiDebuggingSignature(),
	}

	for i := 0; i < b.N; i++ {
		// Produce events
		eventsCh := make(chan types.Event, inputEventsCount)
		ProduceEventsInMemory(eventsCh, inputEventsCount)

		inputs := engine.EventSources{
			Tracee: eventsCh,
		}
		output := make(chan types.Finding, inputEventsCount*len(sigs))

		e := engine.NewEngine(sigs, inputs, output, os.Stderr)
		// Start rules engine and wait until all events are processed
		e.Start(waitForEventsProcessed(eventsCh))

		b.Logf("Test is done with %d findings", len(output))
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

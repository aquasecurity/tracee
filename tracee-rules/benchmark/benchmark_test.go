package benchmark

import (
	"fmt"
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

func BenchmarkOnEventCodeInjectionRuleRego(b *testing.B) {
	codeInjectSig, err := rego.NewCodeInjectionSignature()
	require.NoError(b, err)

	err = codeInjectSig.Init(ignoreFinding)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err = codeInjectSig.OnEvent(triggerCodeInjectorPtraceEvent)
		require.NoError(b, err)
	}
}

func BenchmarkOnEventCodeInjectionRuleGo(b *testing.B) {
	codeInjectSig := golang.NewCodeInjectionSignature()
	err := codeInjectSig.Init(ignoreFinding)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := codeInjectSig.OnEvent(triggerCodeInjectorPtraceEvent)
		require.NoError(b, err)
	}
}

func BenchmarkEngineWithCodeInjectionRuleRego(b *testing.B) {
	// Prepare signatures
	codeInjectSig, err := rego.NewCodeInjectionSignature()
	require.NoError(b, err)

	sigs := []types.Signature{
		codeInjectSig,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Produce events without timing it
		b.StopTimer()
		inputs := ProduceEventsInMemory(inputEventsCount)
		output := make(chan types.Finding, inputEventsCount)
		e := engine.NewEngine(sigs, inputs, output, os.Stderr)
		b.StartTimer()

		// Start rules engine and wait until all events are processed
		e.Start(waitForEventsProcessed(inputs.Tracee))

		b.Logf("Test is done with %d findings", len(output))
	}
}

func BenchmarkEngineWithCodeInjectionRuleGo(b *testing.B) {
	// Prepare signatures
	codeInjectSig := golang.NewCodeInjectionSignature()

	sigs := []types.Signature{
		codeInjectSig,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Produce events without timing it
		b.StopTimer()
		inputs := ProduceEventsInMemory(inputEventsCount)
		output := make(chan types.Finding, inputEventsCount)
		e := engine.NewEngine(sigs, inputs, output, os.Stderr)
		b.StartTimer()

		// Start rules engine and wait until all events are processed
		e.Start(waitForEventsProcessed(inputs.Tracee))

		b.Logf("Test is done with %d findings", len(output))
	}
}

func BenchmarkEngineWithMultipleRulesRegoAndGo(b *testing.B) {
	// Prepare signatures
	codeInjectionRegoSig, err := rego.NewCodeInjectionSignature()
	require.NoError(b, err)
	antiDebuggingRegoSig, err := rego.NewAntiDebuggingSignature()
	require.NoError(b, err)

	sigs := []types.Signature{
		codeInjectionRegoSig,
		antiDebuggingRegoSig,

		golang.NewCodeInjectionSignature(),
		golang.NewAntiDebuggingSignature(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Produce events without timing it
		b.StopTimer()
		inputs := ProduceEventsInMemory(inputEventsCount)
		output := make(chan types.Finding, inputEventsCount*len(sigs))
		e := engine.NewEngine(sigs, inputs, output, os.Stderr)
		b.StartTimer()

		// Start rules engine and wait until all events are processed
		e.Start(waitForEventsProcessed(inputs.Tracee))

		b.Logf("Test is done with %d findings", len(output))
	}
}

func BenchmarkEngineWithNSignaturesRego(b *testing.B) {
	testCases := []int{2, 4, 8, 16, 32, 64, 128}
	sig, err := rego.NewCodeInjectionSignature()
	require.NoError(b, err)

	for _, tc := range testCases {
		b.Run(fmt.Sprintf("%dSignatures", tc), func(b *testing.B) {
			sigs := make([]types.Signature, tc)
			for i := range sigs {
				sigs[i] = sig
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Produce events without timing it
				b.StopTimer()
				inputs := ProduceEventsInMemory(inputEventsCount)
				output := make(chan types.Finding, inputEventsCount*len(sigs))
				e := engine.NewEngine(sigs, inputs, output, os.Stderr)
				b.StartTimer()

				// Start rules engine and wait until all events are processed
				e.Start(waitForEventsProcessed(inputs.Tracee))

				b.Logf("Test is done with %d findings", len(output))
			}
		})
	}
}

func BenchmarkEngineWithNSignaturesGo(b *testing.B) {
	testCases := []int{2, 4, 8, 16, 32, 64, 128}
	sig := golang.NewCodeInjectionSignature()

	for _, tc := range testCases {
		b.Run(fmt.Sprintf("%dSignatures", tc), func(b *testing.B) {
			sigs := make([]types.Signature, tc)
			for i := range sigs {
				sigs[i] = sig
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Produce events without timing it
				b.StopTimer()
				inputs := ProduceEventsInMemory(inputEventsCount)
				output := make(chan types.Finding, inputEventsCount*len(sigs))
				e := engine.NewEngine(sigs, inputs, output, os.Stderr)
				b.StartTimer()

				// Start rules engine and wait until all events are processed
				e.Start(waitForEventsProcessed(inputs.Tracee))

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

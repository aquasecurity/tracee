package proctree

import (
	"context"
	"strconv"
	"sync"
	"testing"
)

func BenchmarkProcessTree(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	config := ProcTreeConfig{
		Source:               SourceBoth,
		ProcessCacheSize:     DefaultProcessCacheSize,
		ThreadCacheSize:      DefaultThreadCacheSize,
		ProcfsInitialization: false,
		ProcfsQuerying:       false,
	}

	pt, err := NewProcessTree(ctx, config)
	if err != nil {
		b.Fatalf("failed to create ProcessTree: %v", err)
	}

	benchmarks := []struct {
		name      string
		benchFunc func(b *testing.B, pt *ProcessTree, concurrency int)
	}{
		{"GetProcessByHash", benchmarkGetProcessByHash},
		{"GetOrCreateProcessByHash", benchmarkGetOrCreateProcessByHash},
		{"GetThreadByHash", benchmarkGetThreadByHash},
		{"GetOrCreateThreadByHash", benchmarkGetOrCreateThreadByHash},
	}

	concurrencyLevels := []int{1, 2, 4, 8}

	for _, bm := range benchmarks {
		for _, concurrency := range concurrencyLevels {
			b.Run(bm.name+"-Concurrency"+strconv.Itoa(concurrency), func(b *testing.B) {
				bm.benchFunc(b, pt, concurrency)
			})
		}
	}
}

func benchmarkGetProcessByHash(b *testing.B, pt *ProcessTree, concurrency int) {
	var wg sync.WaitGroup
	wg.Add(concurrency)

	startSignal := make(chan struct{})

	for i := 0; i < concurrency; i++ {
		go func(i int) {
			defer wg.Done()
			<-startSignal
			for n := 0; n < b.N; n++ {
				pt.GetProcessByHash(uint32(i))
			}
		}(i)
	}

	b.ResetTimer()
	close(startSignal)
	wg.Wait()
}

func benchmarkGetOrCreateProcessByHash(b *testing.B, pt *ProcessTree, concurrency int) {
	var wg sync.WaitGroup
	wg.Add(concurrency)

	startSignal := make(chan struct{})

	for i := 0; i < concurrency; i++ {
		go func(i int) {
			defer wg.Done()
			<-startSignal
			for n := 0; n < b.N; n++ {
				pt.GetOrCreateProcessByHash(uint32(i))
			}
		}(i)
	}

	b.ResetTimer()
	close(startSignal)
	wg.Wait()
}

func benchmarkGetThreadByHash(b *testing.B, pt *ProcessTree, concurrency int) {
	var wg sync.WaitGroup
	wg.Add(concurrency)

	startSignal := make(chan struct{})

	for i := 0; i < concurrency; i++ {
		go func(i int) {
			defer wg.Done()
			<-startSignal
			for n := 0; n < b.N; n++ {
				pt.GetThreadByHash(uint32(i))
			}
		}(i)
	}

	b.ResetTimer()
	close(startSignal)
	wg.Wait()
}

func benchmarkGetOrCreateThreadByHash(b *testing.B, pt *ProcessTree, concurrency int) {
	var wg sync.WaitGroup
	wg.Add(concurrency)

	startSignal := make(chan struct{})

	for i := 0; i < concurrency; i++ {
		go func(i int) {
			defer wg.Done()
			<-startSignal
			for n := 0; n < b.N; n++ {
				pt.GetOrCreateThreadByHash(uint32(i))
			}
		}(i)
	}

	b.ResetTimer()
	close(startSignal)
	wg.Wait()
}

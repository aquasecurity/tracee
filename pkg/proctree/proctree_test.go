package proctree

import (
	"context"
	"sync"
	"testing"
)

// TestProcessTreeConcurrency tests the ProcessTree for concurrent access.
// Enable data race detection with `go test -race`.
func TestProcessTreeConcurrency(t *testing.T) {
	t.Parallel()
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
		t.Fatalf("failed to create ProcessTree: %v", err)
	}

	var wg sync.WaitGroup
	startSignal := make(chan struct{})

	testFunc := func(hash uint32) {
		defer wg.Done()

		<-startSignal // Wait for the signal to start

		// Public methods
		pt.GetProcessByHash(hash)
		pt.GetOrCreateProcessByHash(hash)
		pt.GetThreadByHash(hash)
		pt.GetOrCreateThreadByHash(hash)
	}

	// Run tests concurrently for different hashes
	for i := 0; i < 3000; i++ {
		wg.Add(1)
		go testFunc(uint32(i))
	}

	// Run tests concurrently for the same hash
	for i := 0; i < 3000; i++ {
		wg.Add(1)
		go testFunc(42)
	}

	// Signal all goroutines to start at the same time
	close(startSignal)

	wg.Wait()
}

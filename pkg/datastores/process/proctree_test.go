package process

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

	testFunc := func(taskHash uint32) {
		defer wg.Done()

		<-startSignal // Wait for the signal to start

		// Public methods
		pt.GetProcessByHash(taskHash)
		pt.GetOrCreateProcessByHash(taskHash)
		pt.GetThreadByHash(taskHash)
		pt.GetOrCreateThreadByHash(taskHash)
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

// TestHashCalculationConsistency verifies that procfs and kernel signal hash calculations
// produce the same results for the same process. This tests the fix for GitHub issue #4868.
func TestHashCalculationConsistency(t *testing.T) {
	t.Parallel()

	// Test data representing the same process
	pid := uint32(12345)

	// Simulate realistic scenario from the bug report
	// System has been running for some time, so boot time != epoch time
	bootTimeOffssetNs := uint64(1754327201505193969)                                  // Boot time offset from bug report
	processStartBootNsFromSignal := uint64(1524976129897580)                          // Process start time since boot (from signal, high precision)
	processStartBootNsFromProcfs := uint64(1524976120000000)                          // Process start time since boot (from procfs, low precision - rounded to ticks)
	processStartEpochNsFromSignal := bootTimeOffssetNs + processStartBootNsFromSignal // Total epoch time from signal
	processStartEpochNsFromProcfs := bootTimeOffssetNs + processStartBootNsFromProcfs // Total epoch time from procfs

	// OLD approach (what procfs was doing WRONG)
	// It was using boot time directly for hash calculation
	oldProcfsHash := HashTaskID(pid, processStartBootNsFromProcfs)

	// NEW approach (what procfs does now CORRECTLY)
	// Convert boot time to epoch time before hash calculation
	newProcfsHash := HashTaskID(pid, processStartEpochNsFromProcfs)

	// Kernel signal approach (what kernel signals always did CORRECTLY)
	// Kernel signals provide epoch time directly
	kernelSignalHash := HashTaskID(pid, processStartEpochNsFromSignal)

	// Verify that the new procfs approach matches kernel signals (THE FIX)
	if newProcfsHash != kernelSignalHash {
		t.Errorf("Hash mismatch after fix: newProcfs=%d, kernelSignal=%d", newProcfsHash, kernelSignalHash)
	}

	// Verify that the old approach was different (demonstrating THE BUG)
	if oldProcfsHash == kernelSignalHash {
		t.Error("Old procfs hash should NOT match kernel signal hash (this demonstrates the bug)")
		t.Error("  If they match, the test conditions don't reproduce the original bug")
	}
}

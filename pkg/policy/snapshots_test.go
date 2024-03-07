package policy

import (
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/pkg/logger"
)

func setPruneFunc(snaps *snapshots) {
	snaps.SetPruneFunc(func(policies Policies) []error {
		errs := []error{}
		ps := policies.(*Policies)
		for _, bpfMap := range ps.versionBPFMaps {
			err := syscall.Close(bpfMap.FileDescriptor())
			if err != nil {
				errs = append(errs, err)
			}
		}

		return errs
	})
}

func TestStoreSnapshot(t *testing.T) {
	snaps := newSnapshots()

	ps := &Policies{}
	snaps.Store(ps)
	assert.Equal(t, uint16(1), uint16(ps.version))

	// after storing the snapshot, there should be one snapshot available
	lastSnapshot, err := snaps.GetLast()
	assert.NoError(t, err)
	assert.Equal(t, ps, lastSnapshot)
}

func TestGetSnapshot(t *testing.T) {
	snaps := newSnapshots()

	ps := &Policies{}
	snaps.Store(ps)

	// get the snapshot for the version just stored
	snapshot, err := snaps.Get(1) // since our lastVersion starts at 0 and increments on StoreSnapshot
	assert.NoError(t, err)
	assert.Equal(t, ps, snapshot)

	// try getting a snapshot for a version that does not exist
	_, err = snaps.Get(1000)
	assert.Error(t, err)
}

func TestGetLastSnapshot(t *testing.T) {
	snaps := newSnapshots()

	ps1 := &Policies{}
	snaps.Store(ps1)

	ps2 := &Policies{}
	snaps.Store(ps2)

	// after storing two snapshots, the last one should be ps2
	lastSnapshot, err := snaps.GetLast()
	assert.NoError(t, err)
	assert.Equal(t, ps2, lastSnapshot)
}

func TestCircularBufferOverwrite(t *testing.T) {
	snaps := newSnapshots()
	setPruneFunc(snaps)

	// create and store maxSnapshots
	for i := 0; i < maxSnapshots; i++ {
		ps := &Policies{}
		snaps.Store(ps)
		assert.Equal(t, uint16(i+1), uint16(ps.version))
	}

	// the last stored snapshot is for version maxSnapshots
	lastSnapshotBeforeOverwrite, err := snaps.GetLast()
	assert.NoError(t, err)

	// store one more snapshot to overwrite the first snapshot in the buffer
	psOverwrite := &Policies{}
	snaps.Store(psOverwrite)
	assert.Equal(t, uint16(maxSnapshots+1), psOverwrite.version)

	// check if the oldest snapshot (version 1) has been overwritten
	_, err = snaps.Get(1)
	assert.Error(t, err, "expected error when retrieving overwritten snapshot")

	// check the last snapshot is the one just stored
	lastSnapshotAfterOverwrite, err := snaps.GetLast()
	assert.NoError(t, err)
	assert.Equal(t, psOverwrite, lastSnapshotAfterOverwrite)

	// ensure the previous last snapshot is still retrievable
	previousVersion := uint16(maxSnapshots)
	snapshot, err := snaps.Get(previousVersion)
	assert.NoError(t, err)
	assert.Equal(t, lastSnapshotBeforeOverwrite, snapshot, "the last snapshot before overwrite should still be retrievable")
}

func TestConcurrentSnapshots(t *testing.T) {
	snaps := newSnapshots()
	setPruneFunc(snaps)

	const (
		numStoreRoutines    = 300
		numRetrieveRoutines = 1000
	)
	var (
		readyForRetrieve int32
		mainWG           sync.WaitGroup
		innerWG          sync.WaitGroup // for inner goroutines
		firstStoreDone   sync.WaitGroup
	)

	// use a channel to coordinate the start of storing goroutines
	startStoreCh := make(chan struct{})

	mainWG.Add(2) // two main goroutines: one for storing and one for retrieving

	firstStoreDone.Add(1) // only one is required to signal when storing is done
	// spawn a goroutine to initiate n goroutines for storing snapshots
	go func() {
		defer mainWG.Done()

		for i := 0; i < numStoreRoutines; i++ {
			innerWG.Add(1)

			go func() {
				defer innerWG.Done()

				// wait for the start signal
				<-startStoreCh

				// store a snapshot
				ps := &Policies{}
				snaps.Store(ps)

				if atomic.CompareAndSwapInt32(&readyForRetrieve, 0, 1) {
					firstStoreDone.Done() // signal the retrieving goroutines to start
				}
			}()
		}
	}()

	// spawn a goroutine to initiate n goroutines for retrieving the last snapshot
	go func() {
		defer mainWG.Done()

		for i := 0; i < numRetrieveRoutines; i++ {
			innerWG.Add(1)

			go func() {
				defer innerWG.Done()

				// ensure a snapshot has been stored before trying to retrieve
				firstStoreDone.Wait()

				// retrieve the last snapshot
				_, err := snaps.GetLast()
				assert.NoError(t, err)
			}()
		}
	}()

	// signal storing goroutines to start their tasks
	close(startStoreCh)

	// wait for the two main goroutines to complete
	mainWG.Wait()

	// wait for all inner goroutines to complete
	innerWG.Wait()

	// get the last stored snapshot
	lastSnapshot, err := snaps.GetLast()
	last := lastSnapshot.(*Policies)
	assert.NoError(t, err)
	assert.Equal(t, uint16(numStoreRoutines), uint16(last.version))

	// get the numStoreRoutines-10th snapshot
	snapshot, err := snaps.Get(uint16(numStoreRoutines - 10))
	nSnap := snapshot.(*Policies)
	assert.NoError(t, err)
	assert.Equal(t, uint16(numStoreRoutines-10), uint16(nSnap.version))

	// post-check to ensure storedCnt is as expected, given the concurrency
	assert.True(t, snaps.storedCnt <= maxSnapshots, "Stored count should never exceed maxSnapshots")
}

func TestWrapAround(t *testing.T) {
	snaps := newSnapshots()

	// set the lastVersion to its maximum value minus 1
	snaps.lastVersion = math.MaxUint16 - 1

	// store a snapshot, this should increase version to math.MaxUint16
	ps1 := &Policies{}
	snaps.Store(ps1)

	// verify that the version is set to math.MaxUint16
	assert.Equal(t, uint16(math.MaxUint16), uint16(ps1.version))

	// store another snapshot, this should trigger the wrap-around and reset the version to 1
	ps2 := &Policies{}
	snaps.Store(ps2)

	// verify that the wrap-around occurred
	assert.Equal(t, uint16(1), uint16(ps2.version))
}

func TestPruneSnapshotsOlderThan(t *testing.T) {
	snaps := newSnapshots()
	setPruneFunc(snaps)

	const (
		timeToPrune  = 250 * time.Millisecond // 0.25 seconds
		numSnapshots = maxSnapshots           // number of snapshots to store in one go
	)

	// Helper function to store numSnapshots snapshots immediately
	storeSnapshots := func() {
		for i := 0; i < numSnapshots; i++ {
			ps := &Policies{}
			snaps.Store(ps)
		}
	}

	// store and prune three times
	for iteration := 1; iteration <= 3; iteration++ {
		storeSnapshots()

		// Sleep for the desired prune time to ensure all snapshots are older than this duration
		time.Sleep(timeToPrune)

		errs := snaps.PruneSnapshotsOlderThan(timeToPrune)
		assert.Empty(t, errs)

		logger.Infow(
			fmt.Sprintf("iteration %d", iteration),
			"stored", numSnapshots,
			"pruned", numSnapshots-1,
			"remaining", snaps.storedCnt,
		)

		// Despite pruning all older snapshots, we expect to have one snapshot
		// as the last snapshot is always retained.
		assert.Equal(t, 1, int(snaps.storedCnt))
	}
}

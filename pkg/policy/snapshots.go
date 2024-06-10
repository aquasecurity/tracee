package policy

import (
	"sync"
	"time"

	"github.com/aquasecurity/tracee/logger"
	"github.com/aquasecurity/tracee/pkg/errfmt"
)

const (
	maxSnapshots = PolicyMax
)

// snapshot is a snapshot of the Policies at a given version.
type snapshot struct {
	time     time.Time
	version  uint16
	policies *Policies
}

// snapshots is a circular buffer of snapshots.
type snapshots struct {
	murw        sync.RWMutex
	lastVersion uint16
	snaps       [maxSnapshots]*snapshot
	nextIdx     int
	lastIdx     int
	storedCnt   int
	prune       func(*Policies) []error
}

var (
	snaps     *snapshots // singleton
	snapsOnce sync.Once
)

// newSnapshots creates a new snapshot.
func newSnapshots() *snapshots {
	return &snapshots{
		murw:        sync.RWMutex{},
		lastVersion: 0,
		snaps:       [maxSnapshots]*snapshot{},
		nextIdx:     0,
		lastIdx:     -1, // no snapshots stored
		storedCnt:   0,
		prune:       nil,
	}
}

func Snapshots() *snapshots {
	snapsOnce.Do(func() {
		snaps = newSnapshots()
	})

	return snaps
}

// TODO: This is a temporary solution to allow testing. We must make the constructor
// public and pass the prune function as a parameter.
// SetPruneFunc sets the prune function to be called by PruneSnapshotsOlderThan
// and Store (when overwriting a snapshot).
func (s *snapshots) SetPruneFunc(prune func(*Policies) []error) {
	s.murw.Lock()
	defer s.murw.Unlock()

	s.prune = prune
}

// Store stores a snapshot of the Policies.
func (s *snapshots) Store(ps *Policies) {
	s.murw.Lock()
	defer s.murw.Unlock()

	s.lastVersion++ // new version
	if s.lastVersion == 0 {
		logger.Warnw("Policies version has wrapped around, resetting to 1")
		s.lastVersion++
	}

	ps.version = s.lastVersion // set new version in Policies

	snap := &snapshot{
		time:     time.Now(),
		version:  s.lastVersion,
		policies: ps,
	}

	nextSlot := s.snaps[s.nextIdx]
	if nextSlot != nil {
		if s.prune == nil {
			logger.Warnw("prune function not set, snapshot will not be pruned, only overwritten", "version", nextSlot.version)
		} else {
			errs := s.prune(nextSlot.policies)
			for _, err := range errs {
				logger.Errorw("failed to prune snapshot", "version", nextSlot.version, "error", err)
			}
		}
	}
	s.snaps[s.nextIdx] = snap
	s.lastIdx = s.nextIdx
	s.nextIdx = (s.nextIdx + 1) % maxSnapshots

	if s.storedCnt < maxSnapshots {
		s.storedCnt++
	}
}

// Get returns a snapshot of the Policies at a given version.
func (s *snapshots) Get(polsVersion uint16) (*Policies, error) {
	s.murw.RLock()
	defer s.murw.RUnlock()

	if s.storedCnt == 0 {
		return nil, errfmt.Errorf("no snapshots stored")
	}

	// start from the most recent snapshot
	startIdx := s.lastIdx
	for i := 0; i < s.storedCnt; i++ {
		idx := (startIdx - i + maxSnapshots) % maxSnapshots
		snap := s.snaps[idx]
		if snap.version == polsVersion {
			return snap.policies, nil
		}
	}

	return nil, errfmt.Errorf("no snapshot found for version %d", polsVersion)
}

// GetLast returns the most recent snapshot of the Policies.
func (s *snapshots) GetLast() (*Policies, error) {
	s.murw.RLock()
	defer s.murw.RUnlock()

	if s.storedCnt == 0 {
		return nil, errfmt.Errorf("no snapshots stored")
	}

	return s.snaps[s.lastIdx].policies, nil
}

// TODO: call this function periodically
// PruneSnapshotsOlderThan prunes snapshots older than a given duration.
func (s *snapshots) PruneSnapshotsOlderThan(d time.Duration) []error {
	s.murw.Lock()
	defer s.murw.Unlock()

	if s.storedCnt <= 1 {
		return nil
	}

	if s.prune == nil {
		logger.Errorw("prune function not set, snapshots cannot be pruned")
		return nil
	}

	errs := []error{}
	boundaryIdx := s.lastIdx
	if boundaryIdx == 0 {
		boundaryIdx = maxSnapshots
	}

	// start from the oldest snapshot and iterate through all slots
	startIdx := s.nextIdx
	for i := 0; i < maxSnapshots; i++ {
		idx := (startIdx + i) % maxSnapshots

		// Stop iterating when we reach the boundary. This is to avoid
		// pruning the last snapshot (which is always in use).
		if idx == boundaryIdx {
			break
		}

		snap := s.snaps[idx]
		if snap == nil { // empty slot
			continue
		}

		// As the circular buffer is chronologically ordered, we can stop
		// iterating as soon as we find a snapshot that is not older than d.
		if time.Since(snap.time) <= d {
			break
		}

		errs = append(errs, s.prune(snap.policies)...)

		// remove snapshot even if pruning failed
		s.snaps[idx] = nil
		s.storedCnt--
	}

	return errs
}

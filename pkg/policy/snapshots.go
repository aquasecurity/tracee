package policy

import (
	"sync"

	"golang.org/x/sys/unix"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
)

const (
	maxSnapshots = MaxPolicies
)

type snapshot struct {
	timestamp int64
	policies  *Policies
}

type Snapshots struct {
	murw      sync.RWMutex
	snaps     [maxSnapshots]*snapshot
	nextIdx   int
	storedCnt int
}

var snapshots = &Snapshots{
	snaps:     [maxSnapshots]*snapshot{},
	nextIdx:   0,
	storedCnt: 0,
}

func (ps *Policies) StoreSnapshot() (int64, error) {
	snapshots.murw.Lock()
	defer snapshots.murw.Unlock()

	uptime, err := clockGetTimeMonoTonic()
	if err != nil {
		return 0, errfmt.Errorf("failed to get uptime: %s", err)
	}
	snap := &snapshot{
		timestamp: uptime,
		policies:  ps,
	}

	snapshots.snaps[snapshots.nextIdx] = snap
	snapshots.nextIdx = (snapshots.nextIdx + 1) % maxSnapshots

	if snapshots.storedCnt < maxSnapshots {
		snapshots.storedCnt++
	}

	return snap.timestamp, nil
}

func GetSnapshot(evtTimestamp int64) (*Policies, error) {
	snapshots.murw.RLock()
	defer snapshots.murw.RUnlock()

	if snapshots.storedCnt == 0 {
		return nil, errfmt.Errorf("no snapshots stored")
	}

	for i := snapshots.storedCnt - 1; i >= 0; i-- {
		snap := snapshots.snaps[i]
		if snap.timestamp < evtTimestamp {
			return snap.policies, nil
		}
	}

	// this should never happen, but just in case return the latest snapshot
	latest := snapshots.snaps[snapshots.storedCnt-1]
	logger.Errorw("Failed to find policies snapshot for event", "event_timestamp", evtTimestamp, "snapshot_timestamp", latest.timestamp)
	return latest.policies, nil
}

func GetLastSnapshot() (*Policies, error) {
	snapshots.murw.RLock()
	defer snapshots.murw.RUnlock()

	if snapshots.storedCnt == 0 {
		return nil, errfmt.Errorf("no snapshots stored")
	}

	return snapshots.snaps[snapshots.storedCnt-1].policies, nil
}

func clockGetTimeMonoTonic() (int64, error) {
	var ts unix.Timespec

	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, errfmt.Errorf("getting clock time %v", err)
	}

	return ts.Nano(), nil
}

package container

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/pkg/datastores/container/runtime"
)

func TestParseContainerIdFromCgroupPath(t *testing.T) {
	tests := []struct {
		name                string
		cgroupPath          string
		expectedContainerId string
		expectedRuntime     runtime.RuntimeId
		expectedIsRoot      bool
	}{
		{
			name:                "docker systemd format",
			cgroupPath:          "/kubepods/besteffort/pod123/docker-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef.scope",
			expectedContainerId: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			expectedRuntime:     runtime.Docker,
			expectedIsRoot:      true,
		},
		{
			name:                "crio systemd format without conmon",
			cgroupPath:          "/kubepods/besteffort/pod123/crio-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef.scope",
			expectedContainerId: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			expectedRuntime:     runtime.Crio,
			expectedIsRoot:      true,
		},
		{
			// not a container - for more see parseContainerIdFromCgroupPath() logic
			name:                "crio systemd format with conmon prefix (Unknown)",
			cgroupPath:          "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podb13213a6_d47e_4bd1_bc00_f175d1ad3b6e.slice/crio-conmon-eb5a56051cf7c5e9e588d0dca94d6673d67d43604686e1485984732b18701057.scope",
			expectedContainerId: "",
			expectedRuntime:     runtime.Unknown,
			expectedIsRoot:      false,
		},
		{
			name:                "cri-containerd systemd format",
			cgroupPath:          "/kubepods/besteffort/pod123/cri-containerd-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef.scope",
			expectedContainerId: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			expectedRuntime:     runtime.Containerd,
			expectedIsRoot:      true,
		},
		{
			name:                "containerd with colon separator",
			cgroupPath:          "/kubepods/besteffort/pod123/some:cri-containerd:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			expectedContainerId: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			expectedRuntime:     runtime.Containerd,
			expectedIsRoot:      true,
		},
		{
			name:                "libpod/podman systemd format",
			cgroupPath:          "/machine.slice/libpod-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef.scope",
			expectedContainerId: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			expectedRuntime:     runtime.Podman,
			expectedIsRoot:      true,
		},
		{
			// not a container - for more see parseContainerIdFromCgroupPath() logic
			name:                "podman systemd format with conmon prefix (Unknown)",
			cgroupPath:          "/machine.slice/libpod-conmon-64de256b4158dbfd331e27f93bf807f141883be795fd1b2ae7f40294f32c5bfd.scope",
			expectedContainerId: "",
			expectedRuntime:     runtime.Unknown,
			expectedIsRoot:      false,
		},
		{
			name:                "docker non-systemd format",
			cgroupPath:          "/docker/1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			expectedContainerId: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			expectedRuntime:     runtime.Docker,
			expectedIsRoot:      true,
		},
		{
			name:                "containerd with pod prefix",
			cgroupPath:          "/kubepods/besteffort/pod123/1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			expectedContainerId: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			expectedRuntime:     runtime.Containerd,
			expectedIsRoot:      true,
		},
		{
			name:                "non-container path",
			cgroupPath:          "/user.slice/user-1000.slice",
			expectedContainerId: "",
			expectedRuntime:     runtime.Unknown,
			expectedIsRoot:      false,
		},
		{
			name:                "nested container (should return outer)",
			cgroupPath:          "/kubepods/besteffort/pod123/docker-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef.scope/system.slice",
			expectedContainerId: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			expectedRuntime:     runtime.Docker,
			expectedIsRoot:      false, // not root because there's more after it
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			containerId, containerRuntime, isRoot := parseContainerIdFromCgroupPath(tt.cgroupPath)

			assert.Equal(t, tt.expectedContainerId, containerId, "Container ID mismatch")
			assert.Equal(t, tt.expectedRuntime, containerRuntime, "Runtime mismatch")
			assert.Equal(t, tt.expectedIsRoot, isRoot, "IsRoot mismatch")
		})
	}
}

func TestPurgeExpiredKeepsLiveContainerOnSubCgroupExpiry(t *testing.T) {
	const cid = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	now := time.Now()
	mgr := &Manager{
		cgroupsMap: map[uint32]CgroupDir{
			1: {Path: "/docker-" + cid + ".scope", ContainerId: cid, ContainerRoot: true, Ctime: now.Add(-time.Minute)},
			2: {Path: "/docker-" + cid + ".scope/sub", ContainerId: cid, ContainerRoot: false,
				Ctime: now, Dead: true, expiresAt: now.Add(-time.Second)},
		},
		containerMap: map[string]Container{
			cid: {ContainerId: cid, CreatedAt: now.Add(-time.Minute), Name: "live"},
		},
		deleted: []uint64{2},
	}

	// a sub-cgroup expiry must not purge the live container's entry
	mgr.purgeExpired(now)
	_, subExists := mgr.cgroupsMap[2]
	assert.False(t, subExists, "expired sub-cgroup dir should be deleted")
	cont, ok := mgr.containerMap[cid]
	assert.True(t, ok, "live container entry purged by sub-cgroup expiry")
	assert.Equal(t, "live", cont.Name)
	assert.Empty(t, mgr.deleted)

	// the container root's expiry ends the container
	root := mgr.cgroupsMap[1]
	root.Dead = true
	root.expiresAt = now.Add(-time.Second)
	mgr.cgroupsMap[1] = root
	mgr.deleted = []uint64{1}
	mgr.purgeExpired(now)
	_, ok = mgr.containerMap[cid]
	assert.False(t, ok, "container entry should be purged on root expiry")

	// not-yet-expired entries stay scheduled
	mgr.cgroupsMap[3] = CgroupDir{ContainerId: cid, Dead: true, expiresAt: now.Add(time.Hour)}
	mgr.deleted = []uint64{3}
	mgr.purgeExpired(now)
	_, ok = mgr.cgroupsMap[3]
	assert.True(t, ok)
	assert.Equal(t, []uint64{3}, mgr.deleted)
}

type blockingEnricher struct {
	entered chan struct{}
	release chan struct{}
}

func (b *blockingEnricher) Get(ctx context.Context, containerId string) (runtime.EnrichResult, error) {
	close(b.entered)
	<-b.release
	return runtime.EnrichResult{ContName: "enriched-name", Image: "img:1"}, nil
}

func (b *blockingEnricher) Close() error { return nil }

func TestEnrichCgroupInfoDoesNotHoldLockDuringRPC(t *testing.T) {
	const cid = "feed567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	fake := &blockingEnricher{entered: make(chan struct{}), release: make(chan struct{})}

	var sockets runtime.Sockets
	assert.NoError(t, sockets.Register(runtime.Docker, "/dev/null"))
	svc := runtime.NewService(sockets)
	assert.NoError(t, svc.Register(runtime.Docker,
		func(socket string) (runtime.ContainerEnricher, error) { return fake, nil }))

	now := time.Now()
	mgr := &Manager{
		enricher: svc,
		cgroupsMap: map[uint32]CgroupDir{
			7: {Path: "/docker-" + cid + ".scope", ContainerId: cid, ContainerRoot: true, Ctime: now},
		},
		containerMap: map[string]Container{
			cid: {ContainerId: cid, Runtime: runtime.Docker, CreatedAt: now},
		},
	}

	type result struct {
		cont Container
		err  error
	}
	done := make(chan result, 1)
	go func() {
		cont, err := mgr.EnrichCgroupInfo(7)
		done <- result{cont, err}
	}()

	<-fake.entered
	// the manager lock must be free while the RPC is in flight
	if !mgr.lock.TryLock() {
		t.Fatal("manager lock held across the enrichment RPC")
	}
	// concurrent update while the RPC runs: enrichment must merge onto it
	earlier := now.Add(-time.Minute)
	entry := mgr.containerMap[cid]
	entry.CreatedAt = earlier
	mgr.containerMap[cid] = entry
	mgr.lock.Unlock()

	close(fake.release)
	res := <-done
	assert.NoError(t, res.err)
	assert.Equal(t, "enriched-name", res.cont.Name)
	assert.Equal(t, earlier, res.cont.CreatedAt, "enrichment must not overwrite a concurrently improved CreatedAt")
	assert.Equal(t, "img:1", mgr.containerMap[cid].Image)
}

// stubEnricher returns a fixed result/error, counting calls; if block is
// non-nil, Get waits on it (signal entry via entered, cap >= expected calls).
type stubEnricher struct {
	res     runtime.EnrichResult
	err     error
	calls   atomic.Int32
	entered chan struct{}
	block   chan struct{}
}

func (s *stubEnricher) Get(ctx context.Context, containerId string) (runtime.EnrichResult, error) {
	s.calls.Add(1)
	if s.entered != nil {
		s.entered <- struct{}{}
	}
	if s.block != nil {
		<-s.block
	}
	return s.res, s.err
}

func (s *stubEnricher) Close() error { return nil }

func newTestManager(t *testing.T, enricher runtime.ContainerEnricher) *Manager {
	t.Helper()
	var sockets runtime.Sockets
	if err := sockets.Register(runtime.Docker, "/dev/null"); err != nil {
		t.Fatal(err)
	}
	svc := runtime.NewService(sockets)
	err := svc.Register(runtime.Docker, func(string) (runtime.ContainerEnricher, error) { return enricher, nil })
	if err != nil {
		t.Fatal(err)
	}
	return &Manager{
		enricher:     svc,
		cgroupsMap:   make(map[uint32]CgroupDir),
		containerMap: make(map[string]Container),
	}
}

// waitOrFatal fails the test instead of hanging when a lock-ordering bug
// deadlocks the operation under test.
func waitOrFatal[T any](t *testing.T, ch <-chan T, msg string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(10 * time.Second):
		t.Fatal(msg)
		panic("unreachable")
	}
}

var errFakeDaemon = errors.New("daemon down")

const enrichTestCid = "beef567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

func seedContainer(mgr *Manager, cgroupId uint32, ctime time.Time) {
	mgr.cgroupsMap[cgroupId] = CgroupDir{
		Path: "/docker-" + enrichTestCid + ".scope", ContainerId: enrichTestCid,
		ContainerRoot: true, Ctime: ctime,
	}
	mgr.containerMap[enrichTestCid] = Container{
		ContainerId: enrichTestCid, Runtime: runtime.Docker, CreatedAt: ctime,
	}
}

// TestEnrichCgroupInfoBehaviour pins the pre-restructure semantics of every
// early-return path and of the happy path.
func TestEnrichCgroupInfoBehaviour(t *testing.T) {
	now := time.Now()

	t.Run("unknown cgroup errors without RPC", func(t *testing.T) {
		stub := &stubEnricher{}
		mgr := newTestManager(t, stub)
		_, err := mgr.EnrichCgroupInfo(99)
		assert.ErrorContains(t, err, "not found")
		assert.Zero(t, stub.calls.Load())
	})

	t.Run("non-container cgroup is a no-op", func(t *testing.T) {
		stub := &stubEnricher{}
		mgr := newTestManager(t, stub)
		mgr.cgroupsMap[5] = CgroupDir{Path: "/system.slice/ssh.service", ContainerId: ""}
		cont, err := mgr.EnrichCgroupInfo(5)
		assert.NoError(t, err)
		assert.Empty(t, cont.ContainerId)
		assert.Zero(t, stub.calls.Load())
	})

	t.Run("untracked container errors without RPC", func(t *testing.T) {
		stub := &stubEnricher{}
		mgr := newTestManager(t, stub)
		seedContainer(mgr, 7, now)
		// purged container, lingering cgroup entry
		delete(mgr.containerMap, enrichTestCid)
		_, err := mgr.EnrichCgroupInfo(7)
		assert.ErrorContains(t, err, "no longer tracked")
		assert.Zero(t, stub.calls.Load())
	})

	t.Run("dead cgroup errors without RPC", func(t *testing.T) {
		stub := &stubEnricher{}
		mgr := newTestManager(t, stub)
		seedContainer(mgr, 7, now)
		info := mgr.cgroupsMap[7]
		info.Dead = true
		mgr.cgroupsMap[7] = info
		_, err := mgr.EnrichCgroupInfo(7)
		assert.ErrorContains(t, err, "already deleted")
		assert.Zero(t, stub.calls.Load())
	})

	t.Run("already enriched short-circuits", func(t *testing.T) {
		stub := &stubEnricher{}
		mgr := newTestManager(t, stub)
		seedContainer(mgr, 7, now)
		entry := mgr.containerMap[enrichTestCid]
		entry.Image = "cached:img"
		mgr.containerMap[enrichTestCid] = entry
		cont, err := mgr.EnrichCgroupInfo(7)
		assert.NoError(t, err)
		assert.Equal(t, "cached:img", cont.Image)
		assert.Zero(t, stub.calls.Load())
	})

	t.Run("enricher error leaves state untouched", func(t *testing.T) {
		stub := &stubEnricher{err: errFakeDaemon}
		mgr := newTestManager(t, stub)
		seedContainer(mgr, 7, now)
		_, err := mgr.EnrichCgroupInfo(7)
		assert.ErrorContains(t, err, "daemon down")
		assert.Empty(t, mgr.containerMap[enrichTestCid].Image)
		assert.Equal(t, now, mgr.containerMap[enrichTestCid].CreatedAt)
	})

	t.Run("happy path merges enrichment and preserves identity", func(t *testing.T) {
		stub := &stubEnricher{res: runtime.EnrichResult{ContName: "n1", Image: "img:2"}}
		mgr := newTestManager(t, stub)
		seedContainer(mgr, 7, now)
		cont, err := mgr.EnrichCgroupInfo(7)
		assert.NoError(t, err)
		assert.Equal(t, "n1", cont.Name)
		assert.Equal(t, "img:2", cont.Image)
		assert.Equal(t, enrichTestCid, cont.ContainerId)
		assert.Equal(t, now, cont.CreatedAt)
		assert.Equal(t, runtime.Docker, cont.Runtime)
		assert.Equal(t, cont, mgr.containerMap[enrichTestCid])
		assert.Equal(t, int32(1), stub.calls.Load())
	})
}

// TestEnrichCgroupInfoConcurrentReaders encodes the pipeline-stall regression:
// while the enrichment RPC is in flight, readers (the signatures data source)
// and the removal purge must proceed, not queue behind the RPC.
func TestEnrichCgroupInfoConcurrentReaders(t *testing.T) {
	stub := &stubEnricher{
		res:     runtime.EnrichResult{ContName: "n"},
		entered: make(chan struct{}, 1),
		block:   make(chan struct{}),
	}
	mgr := newTestManager(t, stub)
	seedContainer(mgr, 7, time.Now())

	done := make(chan error, 1)
	go func() {
		_, err := mgr.EnrichCgroupInfo(7)
		done <- err
	}()
	waitOrFatal(t, stub.entered, "enrichment RPC never entered")

	dsDone := make(chan struct{})
	go func() {
		ds := NewDataSource(mgr)
		for i := 0; i < 100; i++ {
			if _, err := ds.Get(enrichTestCid); err != nil {
				break
			}
		}
		close(dsDone)
	}()
	waitOrFatal(t, dsDone, "data source Get blocked behind the enrichment RPC")

	purgeDone := make(chan struct{})
	go func() {
		mgr.lock.Lock()
		mgr.purgeExpired(time.Now())
		mgr.lock.Unlock()
		close(purgeDone)
	}()
	waitOrFatal(t, purgeDone, "purgeExpired blocked behind the enrichment RPC")

	close(stub.block)
	assert.NoError(t, waitOrFatal(t, done, "enrichment never completed"))
	assert.Equal(t, "n", mgr.containerMap[enrichTestCid].Name)
}

// TestEnrichCgroupInfoConcurrentSameCgroup: with the lock released during the
// RPC, two enrichments of the same cgroup may both pass the short-circuit and
// both query - the outcome must be idempotent and deadlock-free.
func TestEnrichCgroupInfoConcurrentSameCgroup(t *testing.T) {
	stub := &stubEnricher{
		res:     runtime.EnrichResult{ContName: "n", Image: "img:1"},
		entered: make(chan struct{}, 2),
		block:   make(chan struct{}),
	}
	mgr := newTestManager(t, stub)
	seedContainer(mgr, 7, time.Now())

	done := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			_, err := mgr.EnrichCgroupInfo(7)
			done <- err
		}()
	}
	waitOrFatal(t, stub.entered, "first enrichment never entered the RPC")
	waitOrFatal(t, stub.entered, "second enrichment serialized behind the first RPC")

	close(stub.block)
	assert.NoError(t, waitOrFatal(t, done, "first enrichment never completed"))
	assert.NoError(t, waitOrFatal(t, done, "second enrichment never completed"))
	assert.Equal(t, "img:1", mgr.containerMap[enrichTestCid].Image)
	assert.Equal(t, int32(2), stub.calls.Load())
}

// TestEnrichCgroupInfoConcurrentRemoval pins the no-resurrection semantics:
// dead/expiry marks set while the RPC runs survive (the stale pre-RPC info is
// not written back), and a cgroup purged mid-RPC is not reintroduced.
func TestEnrichCgroupInfoConcurrentRemoval(t *testing.T) {
	now := time.Now()

	t.Run("dead mark set during RPC survives", func(t *testing.T) {
		stub := &stubEnricher{
			res:     runtime.EnrichResult{ContName: "n", Image: "img:1"},
			entered: make(chan struct{}, 1),
			block:   make(chan struct{}),
		}
		mgr := newTestManager(t, stub)
		seedContainer(mgr, 7, now)

		done := make(chan error, 1)
		go func() {
			_, err := mgr.EnrichCgroupInfo(7)
			done <- err
		}()
		waitOrFatal(t, stub.entered, "enrichment RPC never entered")

		mgr.lock.Lock()
		info := mgr.cgroupsMap[7]
		info.Dead = true
		info.expiresAt = now.Add(30 * time.Second)
		mgr.cgroupsMap[7] = info
		mgr.lock.Unlock()

		close(stub.block)
		assert.NoError(t, waitOrFatal(t, done, "enrichment never completed"))
		assert.True(t, mgr.cgroupsMap[7].Dead, "stale info snapshot written back cleared the Dead mark")
		assert.False(t, mgr.cgroupsMap[7].expiresAt.IsZero())
	})

	t.Run("cgroup purged during RPC is not reintroduced", func(t *testing.T) {
		stub := &stubEnricher{
			res:     runtime.EnrichResult{ContName: "n", Image: "img:1"},
			entered: make(chan struct{}, 1),
			block:   make(chan struct{}),
		}
		mgr := newTestManager(t, stub)
		seedContainer(mgr, 7, now)

		done := make(chan error, 1)
		go func() {
			_, err := mgr.EnrichCgroupInfo(7)
			done <- err
		}()
		waitOrFatal(t, stub.entered, "enrichment RPC never entered")

		mgr.lock.Lock()
		delete(mgr.cgroupsMap, 7)
		delete(mgr.containerMap, enrichTestCid)
		mgr.lock.Unlock()

		close(stub.block)
		assert.NoError(t, waitOrFatal(t, done, "enrichment never completed"))
		_, exists := mgr.containerMap[enrichTestCid]
		assert.False(t, exists, "purged container reintroduced by in-flight enrichment")
	})

	t.Run("container purged during RPC while a sub-cgroup entry lingers", func(t *testing.T) {
		stub := &stubEnricher{
			res:     runtime.EnrichResult{ContName: "n", Image: "img:1"},
			entered: make(chan struct{}, 1),
			block:   make(chan struct{}),
		}
		mgr := newTestManager(t, stub)
		seedContainer(mgr, 7, now)
		// enrichment keyed on a sub-cgroup dir of the same container
		mgr.cgroupsMap[8] = CgroupDir{
			Path: "/docker-" + enrichTestCid + ".scope/sub", ContainerId: enrichTestCid,
			ContainerRoot: false, Ctime: now,
		}

		done := make(chan error, 1)
		go func() {
			_, err := mgr.EnrichCgroupInfo(8)
			done <- err
		}()
		waitOrFatal(t, stub.entered, "enrichment RPC never entered")

		// root expiry purges the container and the root dir; the sub lingers
		mgr.lock.Lock()
		delete(mgr.cgroupsMap, 7)
		delete(mgr.containerMap, enrichTestCid)
		mgr.lock.Unlock()

		close(stub.block)
		assert.NoError(t, waitOrFatal(t, done, "enrichment never completed"))
		_, exists := mgr.containerMap[enrichTestCid]
		assert.False(t, exists,
			"purged container resurrected with zero CreatedAt via a lingering sub-cgroup entry")
	})
}

package container

import (
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

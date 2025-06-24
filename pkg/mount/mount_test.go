package mount_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/pkg/mount"
)

func Test_MountForceFlag(t *testing.T) {
	cfg := mount.Config{
		Source: "/tmp/test",
		FsType: "tmpfs",
		Data:   "size=1M,uid=1000,gid=1000",
		Where:  "/tmp/test",
		Force:  true,
	}
	m, err := mount.NewMountHostOnce(cfg)
	assert.NoError(t, err)
	assert.True(t, m.IsMounted())
	assert.Equal(t, "/tmp/test", m.GetMountpoint())
}

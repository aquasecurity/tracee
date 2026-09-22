package integration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/tests/testutils"
)

const permissionDeniedPathEnv = "TRACEE_RO_MOUNT_PERMISSION_DENIED_PATH"

func waitFileOpenMountDeniedEvent(buf *testutils.EventBuffer, pathname string, timeout time.Duration) *pb.Event {
	return waitEventByField(buf, "file_open_mount_write_denied", "pathname", pathname, timeout)
}

func waitEventByField(buf *testutils.EventBuffer, eventName, fieldName, value string, timeout time.Duration) *pb.Event {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, event := range buf.GetCopy() {
			if event == nil || event.Name != eventName {
				continue
			}
			for _, field := range event.Data {
				if field.Name == fieldName && field.GetStr() == value {
					return event
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil
}

func Test_FileOpenPermissionDeniedHelper(t *testing.T) {
	pathname := os.Getenv(permissionDeniedPathEnv)
	if pathname == "" {
		t.Skip("helper process only")
	}

	file, err := os.OpenFile(pathname, os.O_WRONLY, 0)
	if file != nil {
		_ = file.Close()
	}
	require.ErrorIs(t, err, syscall.EACCES)
}

func eventBool(t *testing.T, event *pb.Event, name string) bool {
	t.Helper()
	for _, field := range event.Data {
		if field.Name == name {
			return field.GetBool()
		}
	}
	t.Fatalf("event field %q not found", name)
	return false
}

func requireNoFileOpenMountDeniedEvent(t *testing.T, buf *testutils.EventBuffer, pathname string) {
	t.Helper()
	require.Nil(t, waitFileOpenMountDeniedEvent(buf, pathname, 750*time.Millisecond))
}

func Test_FileOpenMountWriteDenied(t *testing.T) {
	testutils.AssureIsRoot(t)

	root, err := os.MkdirTemp("/tmp", "tracee-ro-mount-")
	require.NoError(t, err)
	require.NoError(t, os.Chmod(root, 0o755))
	t.Cleanup(func() { _ = os.RemoveAll(root) })

	source := filepath.Join(root, "source")
	bind := filepath.Join(root, "bind")
	require.NoError(t, os.Mkdir(source, 0o755))
	require.NoError(t, os.Mkdir(bind, 0o755))
	require.NoError(t, syscall.Mount("tmpfs", source, "tmpfs", 0, "size=4m"))
	t.Cleanup(func() { _ = syscall.Unmount(source, syscall.MNT_DETACH) })

	plainName := "plain"
	plainSource := filepath.Join(source, plainName)
	require.NoError(t, os.WriteFile(plainSource, []byte("tracee"), 0o666))

	require.NoError(t, syscall.Mount(source, bind, "", syscall.MS_BIND, ""))
	t.Cleanup(func() { _ = syscall.Unmount(bind, syscall.MNT_DETACH) })
	require.NoError(t, syscall.Mount("", bind, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY, ""))

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	policies := testutils.BuildPoliciesFromEvents([]events.ID{
		events.FileOpenMountWriteDenied,
		events.SecurityFileOpen,
	})
	buf, stop := startSyscallerTracee(ctx, cancel, t, policies)
	defer stop()

	t.Run("bind mount write denial is reported", func(t *testing.T) {
		pathname := filepath.Join(bind, plainName)
		file, err := os.OpenFile(pathname, os.O_WRONLY, 0)
		if file != nil {
			_ = file.Close()
		}
		require.ErrorIs(t, err, syscall.EROFS)

		event := waitFileOpenMountDeniedEvent(buf, pathname, 5*time.Second)
		require.NotNil(t, event)
		require.True(t, eventBool(t, event, "mount_read_only"))
		require.False(t, eventBool(t, event, "filesystem_read_only"))
		require.Nil(t, waitEventByField(buf, "security_file_open", "syscall_pathname", pathname, 500*time.Millisecond))
	})

	t.Run("truncation denial is reported", func(t *testing.T) {
		pathname := filepath.Join(bind, plainName)
		buf.Clear()
		file, err := os.OpenFile(pathname, os.O_WRONLY|os.O_TRUNC, 0)
		if file != nil {
			_ = file.Close()
		}
		require.ErrorIs(t, err, syscall.EROFS)
		require.NotNil(t, waitFileOpenMountDeniedEvent(buf, pathname, 5*time.Second))
	})

	t.Run("creation denial is reported", func(t *testing.T) {
		pathname := filepath.Join(bind, "new-file")
		buf.Clear()
		file, err := os.OpenFile(pathname, os.O_WRONLY|os.O_CREATE, 0o600)
		if file != nil {
			_ = file.Close()
		}
		require.ErrorIs(t, err, syscall.EROFS)
		require.NotNil(t, waitFileOpenMountDeniedEvent(buf, pathname, 5*time.Second))
	})

	t.Run("writable mount is a negative control", func(t *testing.T) {
		pathname := filepath.Join(source, "writable")
		buf.Clear()
		require.NoError(t, os.WriteFile(pathname, []byte("ok"), 0o600))
		requireNoFileOpenMountDeniedEvent(t, buf, pathname)
	})

	t.Run("non-read-only permission denial is distinct", func(t *testing.T) {
		pathname := filepath.Join(source, "permission-denied")
		helperBinary := filepath.Join(root, "permission-denied-helper")
		buf.Clear()
		require.NoError(t, os.WriteFile(pathname, []byte("denied"), 0o444))
		require.NoError(t, exec.Command("/bin/cp", os.Args[0], helperBinary).Run())
		require.NoError(t, os.Chmod(helperBinary, 0o755))

		cmd := exec.CommandContext(ctx, helperBinary, "-test.run=^Test_FileOpenPermissionDeniedHelper$", "-test.v")
		cmd.Env = append(os.Environ(), permissionDeniedPathEnv+"="+pathname)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: 65534, Gid: 65534},
		}
		require.NoError(t, cmd.Run())
		requireNoFileOpenMountDeniedEvent(t, buf, pathname)
	})

	t.Run("filesystem read-only denial is classified", func(t *testing.T) {
		pathname := filepath.Join(source, plainName)
		buf.Clear()
		require.NoError(t, syscall.Mount("", source, "", syscall.MS_REMOUNT|syscall.MS_RDONLY, ""))
		t.Cleanup(func() {
			_ = syscall.Mount("", source, "", syscall.MS_REMOUNT, "")
		})

		file, err := os.OpenFile(pathname, os.O_WRONLY, 0)
		if file != nil {
			_ = file.Close()
		}
		require.ErrorIs(t, err, syscall.EROFS)
		event := waitFileOpenMountDeniedEvent(buf, pathname, 5*time.Second)
		require.NotNil(t, event)
		require.True(t, eventBool(t, event, "filesystem_read_only"))
	})
}

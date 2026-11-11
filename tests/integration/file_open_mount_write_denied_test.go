package integration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/tests/testutils"
)

const (
	permissionDeniedPathEnv = "TRACEE_RO_MOUNT_PERMISSION_DENIED_PATH"
	fileOpenPathEnv         = "TRACEE_RO_MOUNT_OPEN_PATH"
	fileOpenFlagsEnv        = "TRACEE_RO_MOUNT_OPEN_FLAGS"
	fileOpenExpectedEnv     = "TRACEE_RO_MOUNT_OPEN_EXPECTED"
)

func Test_FileOpenMountWriteDeniedHelper(t *testing.T) {
	pathname := os.Getenv(fileOpenPathEnv)
	if pathname == "" {
		t.Skip("helper process only")
	}

	flags, err := strconv.Atoi(os.Getenv(fileOpenFlagsEnv))
	require.NoError(t, err)

	file, openErr := os.OpenFile(pathname, flags, 0o600)
	if file != nil {
		require.NoError(t, file.Close())
	}

	switch os.Getenv(fileOpenExpectedEnv) {
	case "success":
		require.NoError(t, openErr)
	case "erofs":
		require.ErrorIs(t, openErr, syscall.EROFS)
	default:
		t.Fatal("unknown expected open result")
	}
}

func runFileOpenMountWriteDeniedHelper(
	ctx context.Context,
	t *testing.T,
	helperBinary string,
	pathname string,
	flags int,
	expected string,
) {
	t.Helper()
	cmd := exec.CommandContext(ctx, helperBinary, "-test.run=^Test_FileOpenMountWriteDeniedHelper$", "-test.v")
	cmd.Env = append(
		os.Environ(),
		fileOpenPathEnv+"="+pathname,
		fileOpenFlagsEnv+"="+strconv.Itoa(flags),
		fileOpenExpectedEnv+"="+expected,
	)
	output, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "helper output: %s", output)
}

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

	helperBinary := filepath.Join(root, "file-open-helper")
	require.NoError(t, exec.Command("/bin/cp", os.Args[0], helperBinary).Run())
	require.NoError(t, os.Chmod(helperBinary, 0o755))

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	policies := testutils.BuildPoliciesFromEvents([]events.ID{
		events.FileOpenMountWriteDenied,
		events.SecurityFileOpen,
	})
	buf, stop := startSyscallerTracee(ctx, cancel, t, policies)
	defer stop()

	t.Run("bind mount write denial is reported", func(t *testing.T) {
		pathname := filepath.Join(bind, plainName)
		runFileOpenMountWriteDeniedHelper(ctx, t, helperBinary, pathname, os.O_WRONLY, "erofs")

		event := waitFileOpenMountDeniedEvent(buf, pathname, 5*time.Second)
		require.NotNil(t, event)
		require.True(t, eventBool(t, event, "mount_read_only"))
		require.False(t, eventBool(t, event, "filesystem_read_only"))
		require.Nil(t, waitEventByField(buf, "security_file_open", "syscall_pathname", pathname, 500*time.Millisecond))
	})

	t.Run("truncation denial is reported", func(t *testing.T) {
		pathname := filepath.Join(bind, plainName)
		buf.Clear()
		runFileOpenMountWriteDeniedHelper(ctx, t, helperBinary, pathname, os.O_WRONLY|os.O_TRUNC, "erofs")
		require.NotNil(t, waitFileOpenMountDeniedEvent(buf, pathname, 5*time.Second))
	})

	t.Run("creation denial is reported", func(t *testing.T) {
		pathname := filepath.Join(bind, "new-file")
		buf.Clear()
		runFileOpenMountWriteDeniedHelper(ctx, t, helperBinary, pathname, os.O_WRONLY|os.O_CREATE, "erofs")
		require.NotNil(t, waitFileOpenMountDeniedEvent(buf, pathname, 5*time.Second))
	})

	t.Run("writable mount is a negative control", func(t *testing.T) {
		pathname := filepath.Join(source, "writable")
		buf.Clear()
		runFileOpenMountWriteDeniedHelper(ctx, t, helperBinary, pathname, os.O_WRONLY|os.O_CREATE, "success")
		requireNoFileOpenMountDeniedEvent(t, buf, pathname)
	})

	t.Run("non-read-only permission denial is distinct", func(t *testing.T) {
		pathname := filepath.Join(source, "permission-denied")
		buf.Clear()
		require.NoError(t, os.WriteFile(pathname, []byte("denied"), 0o444))

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

		runFileOpenMountWriteDeniedHelper(ctx, t, helperBinary, pathname, os.O_WRONLY, "erofs")
		event := waitFileOpenMountDeniedEvent(buf, pathname, 5*time.Second)
		require.NotNil(t, event)
		require.True(t, eventBool(t, event, "filesystem_read_only"))
	})
}

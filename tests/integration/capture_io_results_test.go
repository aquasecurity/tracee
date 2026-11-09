package integration

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/aquasecurity/tracee/tests/testutils"
)

// Keep these pipe regressions separate from Test_TraceeCapture, whose regular-file
// cases are currently skipped on some kernels (issue #5171).
func Test_TraceeCaptureIOResults(t *testing.T) {
	if os.Geteuid() != 0 || !testutils.IsSudoCmdAvailableForThisUser() {
		t.Skip("requires root and non-interactive sudo to run Tracee and inspect its artifacts")
	}
	// Capture path prefixes are limited to 50 bytes; t.TempDir's test name can exceed that.
	workingDir, err := os.MkdirTemp("", "tracee-io-")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(workingDir)) })
	artifactDir := filepath.Join(workingDir, "artifacts")
	require.NoError(t, os.Mkdir(artifactDir, 0700))
	command := fmt.Sprintf("--events init_namespaces -a dir.path=%s -a file-write.filters=path=%s/pipe* -a file-read.filters=path=%s/pipe*", artifactDir, workingDir, workingDir)
	running := testutils.NewRunningTracee(context.Background(), command)
	ready, err := running.Start(20 * time.Second)
	require.NoError(t, err)
	t.Cleanup(func() {
		if errs := running.Stop(); len(errs) > 0 {
			t.Logf("stopping Tracee: %v", errs)
		}
	})
	require.Equal(t, testutils.TraceeStarted, <-ready)
	type expectation struct {
		name        string
		inode       uint64
		write, read []byte
	}
	var expectations []expectation
	cases := []string{"partial-write", "partial-writev", "empty-iovecs", "partial-readv", "writev-EPIPE", "write-EPIPE", "read-EAGAIN", "read-EOF", "checkpoint"}
	for _, name := range cases {
		pipePath := filepath.Join(workingDir, "pipe-"+name)
		require.NoError(t, unix.Mkfifo(pipePath, 0600))
		reader, err := unix.Open(pipePath, unix.O_RDONLY|unix.O_NONBLOCK, 0)
		require.NoError(t, err)
		writer, err := unix.Open(pipePath, unix.O_WRONLY|unix.O_NONBLOCK, 0)
		require.NoError(t, err)
		// Keep descriptors alive until test cleanup, unless the case closes one explicitly.
		t.Cleanup(func() {
			if reader >= 0 {
				_ = unix.Close(reader)
			}
			if writer >= 0 {
				_ = unix.Close(writer)
			}
		})
		var info unix.Stat_t
		require.NoError(t, unix.Fstat(writer, &info))
		want := expectation{name: name, inode: info.Ino}
		switch name {
		case "write-EPIPE", "writev-EPIPE":
			require.NoError(t, unix.Close(reader))
			reader = -1
			if name == "write-EPIPE" {
				_, err = unix.Write(writer, []byte("must not be captured"))
			} else {
				_, err = unix.Writev(writer, [][]byte{[]byte("not written"), []byte("not captured")})
			}
			require.ErrorIs(t, err, unix.EPIPE)
		case "partial-write", "partial-writev":
			capacity, err := unix.FcntlInt(uintptr(writer), unix.F_SETPIPE_SZ, 4096)
			require.NoError(t, err)
			parts := [][]byte{bytes.Repeat([]byte("a"), capacity/2), bytes.Repeat([]byte("b"), capacity), bytes.Repeat([]byte("c"), capacity/2)}
			requested := bytes.Join(parts, nil)
			var n int
			if name == "partial-write" {
				n, err = unix.Write(writer, requested)
			} else {
				n, err = unix.Writev(writer, parts)
			}
			require.NoError(t, err)
			require.Positive(t, n)
			require.Less(t, n, len(requested))
			want.write = requested[:n]
		case "empty-iovecs":
			n, err := unix.Writev(writer, [][]byte{nil, []byte("abc"), nil, []byte("def")})
			require.NoError(t, err)
			require.Equal(t, 6, n)
			want.write = []byte("abcdef")
		case "partial-readv":
			n, err := unix.Write(writer, []byte("abc"))
			require.NoError(t, err)
			require.Equal(t, 3, n)
			buffers := [][]byte{make([]byte, 2), make([]byte, 32)}
			n, err = unix.Readv(reader, buffers)
			require.NoError(t, err)
			require.Equal(t, 3, n)
			want.write = []byte("abc")
			want.read = bytes.Join(buffers, nil)[:n]
		case "read-EAGAIN":
			_, err = unix.Read(reader, make([]byte, 32))
			require.ErrorIs(t, err, unix.EAGAIN)
		case "read-EOF":
			require.NoError(t, unix.Close(writer))
			writer = -1
			n, err := unix.Read(reader, make([]byte, 32))
			require.NoError(t, err)
			require.Zero(t, n)
		case "checkpoint":
			want.write = []byte("capture checkpoint")
			n, err := unix.Write(writer, want.write)
			require.NoError(t, err)
			require.Equal(t, len(want.write), n)
		}
		expectations = append(expectations, want)
		// Isolate cases even on an unfixed BPF program: failed I/O can flood
		// its capture buffer and must not hide subsequent successful operations.
		coolDown(t, time.Second)
	}
	captureDir := filepath.Join(artifactDir, "out")
	checkpoint := expectations[len(expectations)-1]
	// A successful capture also detects disabled/unsupported capture probes, which
	// would otherwise make all negative cases pass without observing any data.
	require.Eventually(t, func() bool {
		data, err := capturedIOBytes(captureDir, "write", checkpoint.inode)
		return err == nil && bytes.Equal(data, checkpoint.write)
	}, 5*time.Second, 50*time.Millisecond)
	coolDown(t, time.Second)
	require.Empty(t, running.Stop())
	for _, want := range expectations {
		t.Run(want.name, func(t *testing.T) {
			written, err := capturedIOBytes(captureDir, "write", want.inode)
			require.NoError(t, err)
			read, err := capturedIOBytes(captureDir, "read", want.inode)
			require.NoError(t, err)
			require.Len(t, written, len(want.write), "capture only bytes successfully written")
			require.Equal(t, want.write, written)
			require.Len(t, read, len(want.read), "capture only bytes successfully read")
			require.Equal(t, want.read, read)
		})
	}
}

func capturedIOBytes(directory, operation string, inode uint64) ([]byte, error) {
	var matched string
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), operation+".") || !strings.HasSuffix(entry.Name(), fmt.Sprintf(".inode-%d", inode)) {
			return nil
		}
		if matched != "" {
			return fmt.Errorf("multiple captures for %s inode %d", operation, inode)
		}
		matched = path
		return nil
	})
	if err != nil {
		return nil, err
	}
	if matched == "" {
		return nil, nil
	}
	return os.ReadFile(matched)
}

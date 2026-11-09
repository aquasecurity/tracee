package integration

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/aquasecurity/tracee/tests/testutils"
)

// Keep a positive capture assertion outside the kernel-dependent skips in
// Test_TraceeCapture. Missing privileges or disabled capture must fail this test.
func Test_TraceeCapturePipeTypes(t *testing.T) {
	require.True(t, testutils.IsSudoCmdAvailableForThisUser(), "pipe capture regressions require non-interactive sudo")
	if os.Geteuid() != 0 {
		executable, err := os.Executable()
		require.NoError(t, err)
		command := exec.Command("sudo", "-n", executable,
			"-test.run=^Test_TraceeCapturePipeTypes$", "-test.v", "-test.timeout=2m")
		output, err := command.CombinedOutput()
		t.Logf("privileged pipe capture regressions:\n%s", output)
		require.NoError(t, err)
		return
	}
	workingDir, err := os.MkdirTemp("", "tracee-pipes-")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(workingDir)) })
	artifactDir := filepath.Join(workingDir, "artifacts")
	require.NoError(t, os.Mkdir(artifactDir, 0700))

	// Read only the fixture on stdin. Background Go runtime pipe reads can
	// return EAGAIN, whose capture accounting is covered by a separate fix.
	stdinFD := int(os.Stdin.Fd())
	stdin, err := unix.Dup(stdinFD)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, unix.Dup2(stdin, stdinFD))
		require.NoError(t, unix.Close(stdin))
	})

	type fixture struct {
		name           string
		reader, writer int
		pipe           bool
	}
	var anonymous [2]int
	require.NoError(t, unix.Pipe2(anonymous[:], unix.O_NONBLOCK))
	fifoPath := filepath.Join(workingDir, "named.fifo")
	require.NoError(t, unix.Mkfifo(fifoPath, 0600))
	fifoReader, err := unix.Open(fifoPath, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	require.NoError(t, err)
	fifoWriter, err := unix.Open(fifoPath, unix.O_WRONLY|unix.O_NONBLOCK, 0)
	require.NoError(t, err)
	regular, err := unix.Open(filepath.Join(workingDir, "regular"), unix.O_CREAT|unix.O_RDWR, 0600)
	require.NoError(t, err)
	sockets, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_NONBLOCK, 0)
	require.NoError(t, err)
	fixtures := []fixture{
		{"anonymous", anonymous[0], anonymous[1], true},
		{"fifo", fifoReader, fifoWriter, true},
		{"regular", regular, regular, false},
		{"socket", sockets[0], sockets[1], false},
	}
	for _, f := range fixtures {
		t.Cleanup(func() {
			require.NoError(t, unix.Close(f.reader))
			if f.writer != f.reader {
				require.NoError(t, unix.Close(f.writer))
			}
		})
	}

	// Scope by namespace and comm: the pid filter expects host PIDs, whereas
	// os.Getpid returns a namespace-local PID when the suite runs in Docker.
	var pidNamespace unix.Stat_t
	require.NoError(t, unix.Stat("/proc/self/ns/pid", &pidNamespace))
	comm, err := os.ReadFile("/proc/self/comm")
	require.NoError(t, err)
	command := fmt.Sprintf("--scope pidns=%d --scope comm=%s --events init_namespaces -a dir.path=%s -a file-write.filters=type=pipe -a file-read.filters=type=pipe -a file-read.filters=fd=stdin", pidNamespace.Ino, strings.TrimSpace(string(comm)), artifactDir)
	running := testutils.NewRunningTracee(context.Background(), command)
	ready, err := running.Start(20 * time.Second)
	require.NoError(t, err)
	t.Cleanup(func() {
		if errs := running.Stop(); len(errs) > 0 {
			t.Logf("stopping Tracee: %v", errs)
		}
	})
	require.Equal(t, testutils.TraceeStarted, <-ready)
	captureDir := filepath.Join(artifactDir, "out")
	for _, f := range fixtures {
		t.Run(f.name, func(t *testing.T) {
			payload := []byte("<script src=\"/" + f.name + ".js\"></script>\n")
			var writerInfo, readerInfo unix.Stat_t
			require.NoError(t, unix.Fstat(f.writer, &writerInfo))
			require.NoError(t, unix.Fstat(f.reader, &readerInfo))
			n, err := unix.Write(f.writer, payload)
			require.NoError(t, err)
			require.Equal(t, len(payload), n)
			if f.name == "regular" {
				_, err = unix.Seek(f.reader, 0, 0)
				require.NoError(t, err)
			}
			actual := make([]byte, len(payload))
			require.NoError(t, unix.Dup2(f.reader, stdinFD))
			n, err = unix.Read(stdinFD, actual)
			restoreErr := unix.Dup2(stdin, stdinFD)
			require.NoError(t, restoreErr)
			require.NoError(t, err)
			require.Equal(t, len(payload), n)
			require.Equal(t, payload, actual)
			if f.pipe {
				require.Eventually(t, func() bool {
					written, writeErr := capturedPipeTypeBytes(captureDir, "write", writerInfo.Ino)
					read, readErr := capturedPipeTypeBytes(captureDir, "read", readerInfo.Ino)
					return writeErr == nil && readErr == nil && bytes.Equal(payload, written) && bytes.Equal(payload, read)
				}, 5*time.Second, 50*time.Millisecond, "both pipe read and write capture must be enabled")
			}
		})
	}
	// Finish with an observed pipe operation so a missing negative capture is not
	// confused with a producer that has not drained its perf buffer yet.
	checkpoint := []byte("pipe capture checkpoint")
	_, err = unix.Write(anonymous[1], checkpoint)
	require.NoError(t, err)
	var info unix.Stat_t
	require.NoError(t, unix.Fstat(anonymous[1], &info))
	expected := append([]byte("<script src=\"/anonymous.js\"></script>\n"), checkpoint...)
	require.Eventually(t, func() bool {
		data, err := capturedPipeTypeBytes(captureDir, "write", info.Ino)
		return err == nil && bytes.Equal(data, expected)
	}, 5*time.Second, 50*time.Millisecond)
	require.Empty(t, running.Stop())
	for _, f := range fixtures {
		if f.pipe {
			continue
		}
		t.Run(f.name+"-excluded", func(t *testing.T) {
			for _, operation := range []struct {
				kind string
				fd   int
			}{{"write", f.writer}, {"read", f.reader}} {
				var info unix.Stat_t
				require.NoError(t, unix.Fstat(operation.fd, &info))
				data, err := capturedPipeTypeBytes(captureDir, operation.kind, info.Ino)
				require.NoError(t, err)
				require.Empty(t, data, "non-pipe %s must be excluded from %s capture", f.name, operation.kind)
			}
		})
	}
}

func capturedPipeTypeBytes(directory, operation string, inode uint64) ([]byte, error) {
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

package integration

import (
	"context"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/aquasecurity/tracee/tests/testutils"
)

func Test_TraceeCapture(t *testing.T) {
	// Make sure we don't leak any goroutines since we run Tracee many times in this test.
	// If a test case fails, ignore the leak since it's probably caused by the aborted test.
	defer goleak.VerifyNone(t)

	if !testutils.IsSudoCmdAvailableForThisUser() {
		t.Skip("skipping: sudo command is not available for this user")
	}

	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	outputWriteFilter := fmt.Sprintf("write=%s/output*", homeDir)
	outputReadFilter := fmt.Sprintf("read=%s/output*", homeDir)
	pipeWriteFilter := fmt.Sprintf("write=%s/pipe*", homeDir)
	pipeReadFilter := fmt.Sprintf("read=%s/pipe*", homeDir)

	tt := []struct {
		name        string
		coolDown    time.Duration
		directory   string
		writeFilter string
		readFilter  string
		test        func(t *testing.T, captureDir string, workingDir string) error
	}{
		{
			name:        "capture write/read",
			coolDown:    0 * time.Second,
			directory:   "/tmp/tracee/1",
			writeFilter: outputWriteFilter,
			readFilter:  outputReadFilter,
			test:        readWriteCaptureTest,
		},
		{
			name:        "capture write/readv",
			coolDown:    2 * time.Second,
			directory:   "/tmp/tracee/2",
			writeFilter: outputWriteFilter,
			readFilter:  outputReadFilter,
			test:        readWritevCaptureTest,
		},
		{
			name:        "capture pipe write/read",
			coolDown:    2 * time.Second,
			directory:   "/tmp/tracee/3",
			writeFilter: pipeWriteFilter,
			readFilter:  pipeReadFilter,
			test:        readWritePipe,
		},
	}

	// run tests cases
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			coolDown(t, tc.coolDown)
			cmd := fmt.Sprintf("--events init_namespaces -c %s -c %s -c dir:%s", tc.readFilter, tc.writeFilter, tc.directory)
			running := testutils.NewRunningTracee(context.Background(), cmd)

			// start tracee
			ready, runErr := running.Start(20 * time.Second)
			require.NoError(t, runErr)

			r := <-ready // block until tracee is ready (or not)
			switch r {
			case testutils.TraceeStarted:
				t.Logf("  --- started tracee ---")
			case testutils.TraceeFailed:
				t.Fatal("tracee failed to start")
			case testutils.TraceeTimedout:
				t.Fatal("tracee timedout to start")
			case testutils.TraceeAlreadyRunning:
				t.Fatal("tracee is already running")
			}

			var failed bool

			captureDir := tc.directory + "/out/host/"
			err := tc.test(t, captureDir, homeDir)
			if err != nil {
				failed = true
				t.Logf("test %s failed: %v", tc.name, err)
			}
			defer func() {
				t.Logf("removing directory %s", tc.directory)
				err := os.RemoveAll(tc.directory)
				if err != nil {
					t.Logf("failed to remove directory %s: %v", tc.directory, err)
				}
			}()

			cmdErrs := running.Stop() // stop tracee
			if len(cmdErrs) > 0 {
				failed = true
				t.Logf("failed to stop tracee: %v", cmdErrs)
			} else {
				t.Logf("  --- stopped tracee ---")
			}

			if failed {
				t.Fail()
			}
		})
	}
}

func fileCaptureLocation(captureDir string, inode uint64, dev uint64, oper string) string {
	return fmt.Sprintf("%s/%s.dev-%d.inode-%d", captureDir, oper, dev, inode)
}

func readWriteCaptureTest(t *testing.T, captureDir string, workingDir string) error {
	outputFile := fmt.Sprintf("%s/output.txt", workingDir)
	const input string = "Hello World\n"
	file, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer func() {
		err := file.Close()
		if err != nil {
			t.Logf("Error closing file in read/write test: %v", err)
		}
		err = os.Remove(outputFile)
		if err != nil {
			t.Logf("Error closing file in read/write test: %v", err)
		}
	}()

	fi, err := os.Stat(outputFile)
	if err != nil {
		return err
	}

	statInfo, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Logf("type assertion failed: expected *syscall.Stat_t")
	}
	inode := statInfo.Ino

	// Write "Hello World" into the file
	_, err = file.Write([]byte(input))
	if err != nil {
		return err
	}

	// Read from the file
	res, err := os.ReadFile(outputFile)
	if err != nil {
		return err
	}

	return assertEntries(t, captureDir, input, string(res), inode)
}

func readWritevCaptureTest(t *testing.T, captureDir string, workingDir string) error {
	outputFile := fmt.Sprintf("%s/output.txt", workingDir)
	file, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer func() {
		err := file.Close()
		if err != nil {
			t.Logf("Error closing file in read/write test: %v", err)
		}
		err = os.Remove(outputFile)
		if err != nil {
			t.Logf("Error closing file in read/write test: %v", err)
		}
	}()

	fi, err := os.Stat(outputFile)
	if err != nil {
		return err
	}

	statInfo, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Logf("type assertion failed: expected *syscall.Stat_t")
	}
	inode := statInfo.Ino

	// Strings to write
	str1 := "Hello World1\n"
	str2 := "Hello World2\n"
	str3 := "Hello World3\n"

	// Prepare iovecs for writev syscall
	iov := []syscall.Iovec{
		{Base: &[]byte(str1)[0], Len: uint64(len(str1))},
		{Base: &[]byte(str2)[0], Len: uint64(len(str2))},
		{Base: &[]byte(str3)[0], Len: uint64(len(str3))},
	}

	// Write using writev syscall
	_, _, errno := syscall.Syscall(syscall.SYS_WRITEV, uintptr(file.Fd()), uintptr(unsafe.Pointer(&iov[0])), uintptr(len(iov)))
	if errno != 0 {
		return errno
	}

	// Seek back to the beginning of the file
	_, err = file.Seek(0, 0)
	if err != nil {
		return err
	}

	// Prepare iovecs for readv syscall
	buf1 := make([]byte, len(str1))
	buf2 := make([]byte, len(str2))
	buf3 := make([]byte, len(str3))

	iovRead := []syscall.Iovec{
		{Base: &buf1[0], Len: uint64(len(buf1))},
		{Base: &buf2[0], Len: uint64(len(buf2))},
		{Base: &buf3[0], Len: uint64(len(buf3))},
	}

	// Read using readv syscall
	_, _, errno = syscall.Syscall(syscall.SYS_READV, uintptr(file.Fd()), uintptr(unsafe.Pointer(&iovRead[0])), uintptr(len(iovRead)))
	if errno != 0 {
		return errno
	}

	input := strings.Join([]string{str1, str2, str3}, "")
	res := strings.Join([]string{string(buf1), string(buf2), string(buf3)}, "")

	return assertEntries(t, captureDir, input, res, inode)
}

func readWritePipe(t *testing.T, captureDir string, workingDir string) error {
	namedPipe := fmt.Sprintf("%s/pipe_test", workingDir)
	err := syscall.Mkfifo(namedPipe, 0666)
	if err != nil {
		return err
	}
	defer func() {
		err := os.Remove(namedPipe)
		if err != nil {
			t.Logf("failed to remove named pipe: %v", err)
		}
	}()

	const input = "Hello World!\n"

	// Open named pipe
	pipe, err := os.OpenFile(namedPipe, os.O_RDWR, os.ModeNamedPipe)
	if err != nil {
		return err
	}
	defer func() {
		err := pipe.Close()
		if err != nil {
			t.Logf("failed to close named pipe: %v", err)
		}
	}()

	finfo, err := pipe.Stat()
	if err != nil {
		return err
	}
	statInfo, ok := finfo.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("type assertion failed: expected *syscall.Stat_t")
	}
	inode := statInfo.Ino

	// Write "Hello World!" to the named pipe
	_, err = pipe.WriteString(input)
	if err != nil {
		return err
	}

	// Read from the named pipe
	buf := make([]byte, 100)
	n, err := pipe.Read(buf)
	if err != nil {
		return err
	}

	res := string(buf[:n])

	return assertEntries(t, captureDir, input, res, inode)
}

func assertEntries(t *testing.T, captureDir string, input string, readOut string, ino uint64) error {
	// Ensure capture files are generated
	coolDown(t, 5*time.Second)

	entries, err := os.ReadDir(captureDir)
	if err != nil {
		return err
	}

	var (
		readCaptureFile  []byte
		writeCaptureFile []byte
	)

	found := 0
	for _, e := range entries {
		if e.IsDir() {
			return fmt.Errorf("unexpected directory %s in capture dir", e.Name())
		}

		entryName := e.Name()

		if !strings.HasSuffix(entryName, fmt.Sprintf(".inode-%d", ino)) {
			continue
		}
		if strings.HasPrefix(entryName, "read") {
			readCaptureFile, err = os.ReadFile(captureDir + entryName)
			if err != nil {
				return err
			}
			found++
		} else if strings.HasPrefix(entryName, "write") {
			writeCaptureFile, err = os.ReadFile(captureDir + entryName)
			if err != nil {
				return err
			}
			found++
		} else {
			return fmt.Errorf("unexpected entry in capture dir: %s", entryName)
		}
	}
	// Found 2 entries
	if found != 2 {
		return fmt.Errorf("expected 2 entries in capture dir, found %d", found)
	}

	// Compare captured data to expected data
	if string(writeCaptureFile) != input {
		return fmt.Errorf("expected write capture file %s, got %s", input, writeCaptureFile)
	}
	if string(readCaptureFile) != readOut {
		return fmt.Errorf("expected read capture file %s, got %s", readOut, readCaptureFile)
	}

	return nil
}

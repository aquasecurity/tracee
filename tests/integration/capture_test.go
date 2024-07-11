package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/aquasecurity/tracee/pkg/pcaps"
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
		name           string
		coolDown       time.Duration
		directory      string
		captureFilters []string
		test           func(t *testing.T, captureDir string, workingDir string) error
	}{
		{
			name:           "capture write/read",
			coolDown:       0 * time.Second,
			directory:      "/tmp/tracee/1",
			captureFilters: []string{outputWriteFilter, outputReadFilter},
			test:           readWriteCaptureTest,
		},
		{
			name:           "capture write/readv",
			coolDown:       2 * time.Second,
			directory:      "/tmp/tracee/2",
			captureFilters: []string{outputWriteFilter, outputReadFilter},
			test:           readWritevCaptureTest,
		},
		{
			name:           "capture pipe write/read",
			coolDown:       2 * time.Second,
			directory:      "/tmp/tracee/3",
			captureFilters: []string{pipeWriteFilter, pipeReadFilter},
			test:           readWritePipe,
		},
		{
			name:           "capture packet context",
			coolDown:       0 * time.Second,
			directory:      "/tmp/tracee/4",
			captureFilters: []string{"network", "pcap:single,command,container,process"},
			test:           packetContext,
		},
	}

	// run tests cases
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			coolDown(t, tc.coolDown)
			cmd := fmt.Sprintf("--events init_namespaces -c dir:%s", tc.directory)
			for _, filter := range tc.captureFilters {
				cmd = fmt.Sprintf("%s -c %s", cmd, filter)
			}
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

			captureDir := path.Join(tc.directory, "out")
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

func readWriteCaptureTest(t *testing.T, captureDir string, workingDir string) error {
	outputFile := path.Join(workingDir, "output.txt")
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
	outputFile := path.Join(workingDir, "output.txt")
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
	namedPipe := path.Join(workingDir, "pipe_test")
	err := os.Remove(namedPipe)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	err = syscall.Mkfifo(namedPipe, 0666)
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

	hostCaptureDir := path.Join(captureDir, "host")

	entries, err := os.ReadDir(hostCaptureDir)
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
			readCaptureFile, err = os.ReadFile(path.Join(hostCaptureDir, entryName))
			if err != nil {
				return err
			}
			found++
		} else if strings.HasPrefix(entryName, "write") {
			writeCaptureFile, err = os.ReadFile(path.Join(hostCaptureDir, entryName))
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

func getPacketContext(pcapFile string) (pcaps.PacketContext, error) {
	packetContext := pcaps.PacketContext{}

	reader, err := os.Open(pcapFile)
	if err != nil {
		return packetContext, err
	}
	pcapReader, err := pcapgo.NewNgReader(reader, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		return packetContext, err
	}

	// Get the first interface
	iface, err := pcapReader.Interface(0)
	if err != nil {
		return packetContext, err
	}

	// Unmarshal the interface description JSON to PacketContext
	err = json.Unmarshal([]byte(iface.Description), &packetContext)
	return packetContext, err
}

func findProcessPcapFile(dir string, processName string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var pcap string
	found := false
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "ping_") && strings.HasSuffix(entry.Name(), ".pcap") {
			if found {
				return "", fmt.Errorf("found multiple pcap files for process %s", processName)
			}
			pcap = entry.Name()
			found = true
		}
	}
	if !found {
		return "", fmt.Errorf("could not find ping pcap")
	}

	return pcap, nil
}

func assertContext(t *testing.T, pcapFile string, pcapType pcaps.PcapType, hostName *string, containerId *string, processName *string, processID *int) error {
	packetContext, err := getPacketContext(pcapFile)
	if err != nil {
		return err
	}

	// Single pcap should have empty context
	if pcapType == pcaps.Single {
		assert.Nil(t, packetContext.Container)
		assert.Nil(t, packetContext.Kubernetes)
		assert.Equal(t, "", packetContext.HostName)
		assert.Equal(t, "", packetContext.ProcessName)
		assert.Nil(t, packetContext.Process)
		return nil
	}

	// Container, command and process pcaps should have container, kubernetes and hostname info
	if pcapType == pcaps.Container || pcapType == pcaps.Command || pcapType == pcaps.Process {
		assert.NotNil(t, packetContext.Container)
		assert.Equal(t, *containerId, packetContext.Container.ID)
		assert.NotNil(t, packetContext.Kubernetes)
		// TODO: test kubernetes info validity
		assert.Equal(t, *hostName, packetContext.HostName)
	}

	// Command and process pcaps should have process name
	if pcapType == pcaps.Command || pcapType == pcaps.Process {
		assert.Equal(t, *processName, packetContext.ProcessName)
	} else {
		assert.Equal(t, "", packetContext.ProcessName)
	}

	// Process pcaps should have process info
	if pcapType == pcaps.Process {
		assert.NotNil(t, packetContext.Process)
		assert.Equal(t, *processID, packetContext.Process.ProcessID)
	} else {
		assert.Nil(t, packetContext.Process)
	}

	return nil
}

func packetContext(t *testing.T, captureDir string, workingDir string) error {
	var emptyString = ""
	var ping = "ping"

	pcapDir := path.Join(captureDir, "pcap")
	hostName, err := os.Hostname()
	if err != nil {
		return err
	}

	// Ping localhost from host
	cmd := exec.Command("ping", "-c", "1", "127.0.0.1")
	if err := cmd.Run(); err != nil {
		return err
	}
	pid := cmd.Process.Pid

	// Ping localhost from a container (use busybox because it's smaller than alpine)
	cmd = exec.Command("docker", "run", "-d", "--rm", "busybox", "ping", "-c", "1", "127.0.0.1")
	// Get the container ID from the output
	output, err := cmd.Output()
	if err != nil {
		return err
	}
	containerId := strings.TrimSuffix(string(output), "\n")
	containerHostname := containerId[0:12]

	// Ensure packets are written to pcap files
	coolDown(t, 5*time.Second)

	// Test context of single pcap
	err = assertContext(t, path.Join(pcapDir, "single.pcap"), pcaps.Single, nil, nil, nil, nil)
	if err != nil {
		return err
	}

	// Test context of container pcaps
	err = assertContext(t, path.Join(pcapDir, "containers", "host.pcap"), pcaps.Container, &hostName, &emptyString, nil, nil)
	if err != nil {
		return err
	}
	err = assertContext(t, path.Join(pcapDir, "containers", fmt.Sprintf("%s.pcap", containerId[0:11])), pcaps.Container, &containerHostname, &containerId, nil, nil)
	if err != nil {
		return err
	}

	// Test context of command pcaps
	err = assertContext(t, path.Join(pcapDir, "commands", "host", "ping.pcap"), pcaps.Command, &hostName, &emptyString, &ping, nil)
	if err != nil {
		return err
	}
	err = assertContext(t, path.Join(pcapDir, "commands", containerId[0:11], "ping.pcap"), pcaps.Command, &containerHostname, &containerId, &ping, nil)
	if err != nil {
		return err
	}

	// Test context of process pcaps
	pcapFile, err := findProcessPcapFile(path.Join(pcapDir, "processes", "host"), "ping")
	if err != nil {
		return err
	}
	err = assertContext(t, path.Join(pcapDir, "processes", "host", pcapFile), pcaps.Process, &hostName, &emptyString, &ping, &pid)
	if err != nil {
		return err
	}
	pcapFile, err = findProcessPcapFile(path.Join(pcapDir, "processes", containerId[0:11]), "ping")
	if err != nil {
		return err
	}
	var one = 1
	err = assertContext(t, path.Join(pcapDir, "processes", containerId[0:11], pcapFile), pcaps.Process, &containerHostname, &containerId, &ping, &one)
	if err != nil {
		return err
	}

	return nil
}

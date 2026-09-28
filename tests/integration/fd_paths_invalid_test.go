package integration

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/tests/testutils"
)

func fdPathCount(status string) float64 {
	client := &http.Client{Timeout: time.Second}
	response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/metrics", testutils.TraceePort))
	if err != nil {
		return -1
	}
	defer response.Body.Close()
	contents, err := io.ReadAll(response.Body)
	if err != nil {
		return -1
	}
	prefix := fmt.Sprintf("tracee_fd_path_captures_total{status=%q} ", status)
	for _, line := range strings.Split(string(contents), "\n") {
		if value, ok := strings.CutPrefix(line, prefix); ok {
			count, err := strconv.ParseFloat(value, 64)
			if err == nil {
				return count
			}
		}
	}
	return -1
}

func Test_FdPathsInvalidDescriptors(t *testing.T) {
	testutils.AssureIsRoot(t)
	file, err := os.CreateTemp("/tmp", "tracee-invalid-fd-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = file.Close(); _ = os.Remove(file.Name()) })
	_, output, logPath := fdPathTracee(t, "close")
	before := fdPathCount("unavailable")
	require.GreaterOrEqual(t, before, float64(0))
	// Use a high descriptor so the test's HTTP/file reads cannot reuse it.
	fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 10000)
	require.NoError(t, err)
	require.NoError(t, syscall.Close(fd))
	invalid := []int{-1, 1 << 30, fd}
	for _, bad := range invalid {
		require.ErrorIs(t, syscall.Close(bad), syscall.EBADF)
	}
	require.Eventually(t, func() bool {
		seen := map[int32]bool{}
		resolved := false
		for _, event := range fdPathEvents(output) {
			if event.Name != "close" {
				continue
			}
			for _, field := range event.Data {
				if field.Name != "fd" {
					continue
				}
				if value, ok := field.Value.(*pb.EventValue_Int32); ok {
					seen[value.Int32] = true
				}
				resolved = resolved || field.GetStr() == fmt.Sprintf("%d=%s", fd, file.Name())
			}
		}
		return resolved && seen[-1] && seen[1<<30] && seen[int32(fd)]
	}, 10*time.Second, 100*time.Millisecond)
	require.Eventually(t, func() bool { return fdPathCount("unavailable") >= before+3 }, time.Second, 100*time.Millisecond)
	contents, err := os.ReadFile(logPath)
	require.NoError(t, err)
	require.NotContains(t, string(contents), "operation not permitted")
	require.NotContains(t, string(contents), "FD path")
}

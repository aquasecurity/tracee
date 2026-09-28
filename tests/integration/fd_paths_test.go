package integration

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/tests/testutils"
)

// Run the real binary so capability changes are isolated from the test process
// and the singleton cannot inherit bypass mode from another integration test.
func Test_FdPathsWithCapabilities(t *testing.T) {
	if !testutils.IsSudoCmdAvailableForThisUser() {
		t.Skip("sudo command is not available for this user")
	}

	// Keep the path below the map's 64-byte value limit.
	file, err := os.CreateTemp("/tmp", "tracee-fd-")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = file.Close()
		_ = os.Remove(file.Name())
	})
	want := fmt.Sprintf("%d=%s", file.Fd(), file.Name())
	outputPath := filepath.Join(t.TempDir(), "events.json")
	artifactsPath := filepath.Join(t.TempDir(), "artifacts")

	cmd := fmt.Sprintf(
		"--events close --scope pid=%d --enrichment fd-paths --capabilities bypass=false "+
			"--output destinations.fdpaths.format=json --output destinations.fdpaths.path=%s "+
			"--artifacts dir.path=%s",
		os.Getpid(), outputPath, artifactsPath,
	)
	running := testutils.NewRunningTracee(context.Background(), cmd)
	ready, err := running.Start(testutils.TraceeDefaultStartupTimeout)
	t.Cleanup(func() {
		if errs := running.Stop(); len(errs) > 0 {
			t.Logf("stopping tracee: %v", errs)
		}
	})
	require.NoError(t, err)
	require.Equal(t, testutils.TraceeStarted, <-ready, "tracee did not become ready")

	require.NoError(t, file.Close())

	// Assert the complete value: just receiving a close event would also pass
	// when the map lookup fails with EPERM and the FD is left as a number.
	require.Eventually(t, func() bool {
		output, err := os.ReadFile(outputPath)
		if err != nil {
			return false
		}
		for _, line := range bytes.Split(output, []byte{'\n'}) {
			var event pb.Event
			if err := protojson.Unmarshal(line, &event); err != nil {
				continue // The last line may still be being written.
			}
			if event.Name != "close" {
				continue
			}
			for _, arg := range event.Data {
				if arg.Name == "fd" && arg.GetStr() == want {
					return true
				}
			}
		}
		return false
	}, 5*time.Second, 100*time.Millisecond, "expected close event with fd=%q", want)
}

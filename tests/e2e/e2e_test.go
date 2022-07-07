package e2e_test

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type traceeContainer struct {
	testcontainers.Container
}

func runTraceeContainer(ctx context.Context, tempDir string) (*traceeContainer, error) {
	req := testcontainers.ContainerRequest{
		Image:      *traceeImageRef,
		Privileged: true,
		BindMounts: map[string]string{ // container:host
			"/tmp":                 tempDir,           // required for all
			"/etc/os-release-host": "/etc/os-release", // required for all
			"/boot":                "/boot",           // required for all
			"/usr/src":             "/usr/src",        // required for full
			"/lib/modules":         "/lib/modules",    // required for full
		},
		Env: map[string]string{
			"LIBBPFGO_OSRELEASE_FILE": "/etc/os-release-host",
		},
		Name:       "tracee",
		AutoRemove: true,
		// FIXME(danielpacak) It seems that the file written by tracee-ebpf to
		// /tmp/tracee/out/tracee.pid is not a reliable readiness probe on its
		// own. It still may happen that tests are flaky without waiting extra
		// few seconds here.
		// See https://github.com/aquasecurity/tracee/issues/1548 for more
		// details.
		WaitingFor: NewFileExistsStrategy(path.Join(tempDir, "/tracee/out/tracee.pid")).
			WithExtraDelay(10 * time.Second),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed creating tracee container: %w", err)
	}

	return &traceeContainer{Container: container}, nil
}

func runTraceeTesterContainer(ctx context.Context, sigID string) (*traceeContainer, error) {
	req := testcontainers.ContainerRequest{
		Image:      *testerImageRef,
		Entrypoint: []string{"/entrypoint.sh", sigID},
		Privileged: true,
		Name:       "tracee-tester",
		AutoRemove: true,
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed creating tracee tester container: %w", err)
	}

	return &traceeContainer{Container: container}, nil
}

var (
	testerImageRef = flag.String("tracee-tester-image-ref", "docker.io/aquasec/tracee-tester:latest",
		"tracee tester container image reference")
	traceeImageRef = flag.String("tracee-image-ref", "tracee:full",
		"tracee container image reference")
	signatureIDs = flag.String("tracee-signatures", "TRC-2,TRC-3,TRC-4,TRC-5,TRC-7,TRC-9,TRC-10,TRC-11,TRC-12,TRC-14",
		"comma-separated list of tracee signature identifiers")
)

func parseSignatureIDs() []string {
	signatureIDs := strings.Split(*signatureIDs, ",")
	for index, sigID := range signatureIDs {
		signatureIDs[index] = strings.TrimSpace(sigID)
	}
	return signatureIDs
}

// TestTraceeSignatures tests tracee signatures (-tracee-signatures) using the
// specified tracee container image (-tracee-image-ref) and tester container
// image (-tracee-tester-image-ref).
//
// Passing signature identifiers as input to the TestTraceeSignatures allows us
// to use it as a quick smoke test in the PR validation workflow or as
// full-blown end-to-end test run on CRON schedule.
//
// Passing tracee container image reference as input to the TestTraceeSignatures
// allows us to test different flavors of tracee container image, i.e. CO-RE,
// non CO-RE, and CO-RE with custom BTFHub support.
//
//     go test -v -run "TestTraceeSignatures" ./tests/e2e/e2e_test.go \
//            -tracee-image-ref "tracee:full" \
//            -tracee-tester-image-ref "aquasec/tracee-tester:latest" \
//            -tracee-signatures "TRC-2,TRC-3"
func TestTraceeSignatures(t *testing.T) {
	if testing.Short() {
		t.Skip("This is an end-to-end test")
	}
	// TODO Normally we should be using tempDir := t.TempDir() but all files
	// created by tracee-ebpf and entrypoint.sh under /tmp/tracee/ are owned by
	// the root user and cannot be automatically removed by the test Cleanup
	// method.
	tempDir := os.TempDir()
	defer func() {
		os.RemoveAll(tempDir)
	}()

	for _, sigID := range parseSignatureIDs() {
		t.Run(fmt.Sprintf("%s/%s", *traceeImageRef, sigID), func(t *testing.T) {
			ctx := context.Background()

			traceeContainer, err := runTraceeContainer(ctx, tempDir)
			require.NoError(t, err)

			defer traceeContainer.Terminate(ctx)

			err = traceeContainer.StartLogProducer(ctx)
			require.NoError(t, err)

			defer traceeContainer.StopLogProducer()

			traceeContainer.FollowOutput(ErrorLogConsumer(t))

			traceeTesterContainer, err := runTraceeTesterContainer(ctx, sigID)
			require.NoError(t, err)

			defer traceeTesterContainer.Terminate(ctx)

			traceeContainer.assertLogs(t, ctx, sigID)
		})
	}
}

func (tc traceeContainer) assertLogs(t *testing.T, ctx context.Context, sigID string) {
	t.Helper()
	time.Sleep(time.Second * 10) // wait for tracee to detect

	b, err := tc.Logs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	log, err := ioutil.ReadAll(b)
	if err != nil {
		t.Fatal(err)
	}

	assert.Contains(t, string(log), fmt.Sprint("Signature ID: ", sigID))
}

type LogConsumerFunc func(log testcontainers.Log)

func (f LogConsumerFunc) Accept(log testcontainers.Log) {
	f(log)
}

// ErrorLogConsumer returns testcontainers.LogConsumer that prints container
// logs to the error log. Logs will be printed only if the test fails or the
// -test.v flag is set.
func ErrorLogConsumer(t *testing.T) LogConsumerFunc {
	return func(log testcontainers.Log) {
		t.Logf("%s: %s", log.LogType, string(log.Content))
	}
}

type FileExistsStrategy struct {
	startupTimeout time.Duration
	pollInterval   time.Duration
	extraDelay     *time.Duration
	path           string
}

// NewFileExistsStrategy constructs FileExistsStrategy with polling interval of
// 100 milliseconds and startup timeout of 30 seconds by default.
func NewFileExistsStrategy(path string) *FileExistsStrategy {
	return &FileExistsStrategy{
		startupTimeout: 30 * time.Second,
		pollInterval:   100 * time.Millisecond,
		path:           path,
	}
}

// WithPollInterval can be used to override the default polling interval of 100
// milliseconds.
func (ws *FileExistsStrategy) WithPollInterval(pollInterval time.Duration) *FileExistsStrategy {
	ws.pollInterval = pollInterval
	return ws
}

// WithExtraDelay can be used to add an extra delay even if the file already
// exists.
func (ws *FileExistsStrategy) WithExtraDelay(extraDelay time.Duration) *FileExistsStrategy {
	ws.extraDelay = &extraDelay
	return ws
}

// WaitUntilReady implements wait.Strategy#WaitUntilReady by checking whether
// the given file exists.
func (ws *FileExistsStrategy) WaitUntilReady(ctx context.Context, _ wait.StrategyTarget) error {
	ctx, cancelContext := context.WithTimeout(ctx, ws.startupTimeout)
	defer cancelContext()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			exists, err := ws.exists()
			if err != nil {
				return err
			}

			log.Printf("Waiting for file %s (exists? %v)\n", ws.path, exists)

			if exists {
				if ws.extraDelay != nil {
					log.Printf("Waiting extra %s\n", ws.extraDelay)
					time.Sleep(*ws.extraDelay)
				}
				return nil
			} else {
				time.Sleep(ws.pollInterval)
				continue
			}

		}
	}
}

func (ws *FileExistsStrategy) exists() (bool, error) {
	_, err := os.Stat(ws.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

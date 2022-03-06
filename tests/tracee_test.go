package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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
			tempDir:                tempDir,           // required for all
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
		WaitingFor: wait.NewLogStrategy("Loaded"),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, err
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
		return nil, err
	}

	return &traceeContainer{Container: container}, nil
}

var (
	testerImageRef = flag.String("tracee-tester-image-ref", "docker.io/aquasec/tracee-tester:latest",
		"tracee tester container image reference")
	traceeImageRef = flag.String("tracee-image-ref", "tracee:full",
		"tracee container image reference")
	signatureIDs = flag.String("tracee-signatures", "TRC-2,TRC-3,TRC-4,TRC-5,TRC-7,TRC-8,TRC-9,TRC-10,TRC-11,TRC-12,TRC-14",
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
//     go test -v -run "TestTraceeSignatures" ./tests/tracee_test.go \
//            -tracee-image-ref "tracee:full" \
//            -tracee-tester-image-ref "aquasec/tracee-tester:latest" \
//            -tracee-signatures "TRC-2,TRC-3"
func TestTraceeSignatures(t *testing.T) {
	tempDir := os.TempDir()
	defer func() {
		os.RemoveAll(tempDir)
	}()

	for _, sigID := range parseSignatureIDs() {
		t.Run(fmt.Sprintf("%s/%s", *traceeImageRef, sigID), func(t *testing.T) {
			ctx := context.Background()

			traceeContainer, err := runTraceeContainer(ctx, tempDir)
			if err != nil {
				t.Fatal(err)
			}
			defer traceeContainer.Terminate(ctx)

			err = traceeContainer.StartLogProducer(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer traceeContainer.StopLogProducer()

			traceeContainer.FollowOutput(errorLogConsumer(t))

			traceeTesterContainer, err := runTraceeTesterContainer(ctx, sigID)
			if err != nil {
				t.Fatal(err)
			}
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

// errorLogConsumer returns testcontainers.LogConsumer that prints container
// logs to the error log. Logs will be printed only if the test fails or the
// -test.v flag is set.
func errorLogConsumer(t *testing.T) LogConsumerFunc {
	return func(log testcontainers.Log) {
		t.Logf("%s: %s", log.LogType, string(log.Content))
	}
}

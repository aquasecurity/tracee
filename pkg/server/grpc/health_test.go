package grpc

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/aquasecurity/tracee/pkg/ebpf/heartbeat"
	"github.com/aquasecurity/tracee/pkg/server"
)

func TestHealthService_Check(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "tracee-health-tests")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	unixSock := tempDir + "/tracee.sock"
	defer os.Remove(unixSock)

	ctx, cancel := context.WithCancel(context.Background())
	// Don't cancel context until test is done to avoid closing heartbeat
	defer cancel()

	// Initialize heartbeat for testing
	// Use a background context that won't be cancelled to keep heartbeat alive
	bgCtx := context.Background()
	heartbeat.Init(bgCtx, 1*time.Second, 2*time.Second)
	instance := heartbeat.GetInstance()
	require.NotNil(t, instance)
	instance.SetCallback(server.InvokeHeartbeat)
	instance.Start()

	// In tests, manually send pulses since uprobe isn't attached
	pulseCtx, pulseCancel := context.WithCancel(ctx)
	defer pulseCancel()
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				safeSendPulse()
			case <-pulseCtx.Done():
				return
			}
		}
	}()

	grpcServer := New("unix", unixSock)
	grpcServer.EnableHealthService()
	go grpcServer.Start(ctx, nil, nil)

	// Wait for server to start
	require.Eventually(t, func() bool {
		_, err := os.Stat(unixSock)
		return err == nil
	}, 2*time.Second, 10*time.Millisecond)

	// Create health client
	conn, err := grpc.NewClient("unix:"+unixSock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	healthClient := healthpb.NewHealthClient(conn)

	// Send initial pulse immediately
	safeSendPulse()

	// Wait for health service monitor to poll and update status (polls every 2s)
	require.Eventually(t, func() bool {
		resp, err := healthClient.Check(ctx, &healthpb.HealthCheckRequest{})
		return err == nil && resp.Status == healthpb.HealthCheckResponse_SERVING
	}, 5*time.Second, 100*time.Millisecond, "health service should become SERVING")

	// Test overall health (empty service name)
	t.Run("overall health check", func(t *testing.T) {
		resp, err := healthClient.Check(ctx, &healthpb.HealthCheckRequest{})
		require.NoError(t, err)
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.Status)
	})
}

// safeSendPulse safely sends a pulse, recovering from panics if the channel is closed or instance is nil
func safeSendPulse() {
	defer func() {
		recover()
	}()
	if instance := heartbeat.GetInstance(); instance != nil {
		heartbeat.SendPulse()
	}
}

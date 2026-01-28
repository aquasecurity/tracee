package grpc

import (
	"context"
	"time"

	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/aquasecurity/tracee/pkg/ebpf/heartbeat"
)

// HealthService wraps the standard gRPC health server and integrates with Tracee's heartbeat mechanism
type HealthService struct {
	server *health.Server
}

// NewHealthService creates a new HealthService instance
func NewHealthService() *HealthService {
	return &HealthService{
		server: health.NewServer(),
	}
}

// Server returns the underlying health server for registration
func (h *HealthService) Server() *health.Server {
	return h.server
}

// StartMonitor polls heartbeat status and updates gRPC health accordingly.
// It monitors the heartbeat at regular intervals and updates the health status
// for all registered services based on whether the heartbeat is alive.
func (h *HealthService) StartMonitor(ctx context.Context) {
	// Use empty string for overall server health
	// This is sufficient for Kubernetes gRPC probes and most health checking scenarios
	// Individual service health can be added later if needed
	overallService := ""

	// Initialize overall health as NOT_SERVING until heartbeat confirms health
	h.server.SetServingStatus(overallService, healthpb.HealthCheckResponse_NOT_SERVING)

	// Poll at the same interval as the heartbeat ack timeout (2s), since that's
	// the boundary at which IsAlive() state actually changes.
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Set overall health to NOT_SERVING on shutdown
			h.server.SetServingStatus(overallService, healthpb.HealthCheckResponse_NOT_SERVING)
			return
		case <-ticker.C:
			// Poll heartbeat status
			instance := heartbeat.GetInstance()
			status := healthpb.HealthCheckResponse_NOT_SERVING
			if instance != nil && instance.IsAlive() {
				status = healthpb.HealthCheckResponse_SERVING
			}

			// Update overall health status
			h.server.SetServingStatus(overallService, status)
		}
	}
}

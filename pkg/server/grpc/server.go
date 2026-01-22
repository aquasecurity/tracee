package grpc

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/common/logger"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/signatures/engine"
)

type Server struct {
	listener   net.Listener
	protocol   string
	listenAddr string
	server     *grpc.Server
}

func New(protocol, listenAddr string) *Server {
	if protocol == "tcp" {
		listenAddr = ":" + listenAddr
	}

	return &Server{listener: nil, protocol: protocol, listenAddr: listenAddr}
}

func (s *Server) Start(ctx context.Context, t *tracee.Tracee, e *engine.Engine) {
	// Create listener when starting
	lis, err := net.Listen(s.protocol, s.listenAddr)
	if err != nil {
		logger.Errorw("Failed to start GRPC server", "protocol", s.protocol, "address", s.listenAddr, "error", err)
		return
	}

	// Set restrictive permissions on Unix socket
	if s.protocol == "unix" {
		err = os.Chmod(s.listenAddr, 0600)
		if err != nil {
			logger.Errorw("Failed to set permissions on Unix socket. This may leave the socket with insecure permissions and allow unauthorized access.", "path", s.listenAddr, "error", err)
			_ = lis.Close()
			return
		}
	}

	s.listener = lis

	srvCtx, srvCancel := context.WithCancel(ctx)
	defer srvCancel()

	// TODO: allow grpc keep alive configuration from CLI/Configfile
	keepaliveParams := keepalive.ServerParameters{
		Time:    5 * time.Second, // Ping the client if it is idle for 5 seconds to ensure the connection is still active
		Timeout: 1 * time.Second, // Wait 1 second for the ping ack before assuming the connection is dead
	}

	grpcServer := grpc.NewServer(grpc.KeepaliveParams(keepaliveParams))
	s.server = grpcServer
	pb.RegisterTraceeServiceServer(grpcServer, &TraceeService{tracee: t})
	pb.RegisterDiagnosticServiceServer(grpcServer, &DiagnosticService{tracee: t})
	pb.RegisterDataSourceServiceServer(grpcServer, &DataSourceService{sigEngine: e})

	t.RegisterE2eGrpcServices(grpcServer)

	go func() {
		logger.Debugw("Starting grpc server", "protocol", s.protocol, "address", s.listenAddr)
		if err := grpcServer.Serve(s.listener); err != nil {
			logger.Errorw("GRPC server", "error", err)
		}
		srvCancel()
	}()

	select {
	case <-ctx.Done():
		logger.Debugw("Context cancelled, shutting down grpc server")
		s.cleanup()
	// if server error occurred while base ctx is not done, we should exit via this case
	case <-srvCtx.Done():
		s.cleanup()
	}
}

// Address returns the address of the server
func (s *Server) Address() string {
	// For TCP, listenAddr already has a colon prefix (e.g., ":4466")
	// For Unix, listenAddr is just the path (e.g., "/var/run/tracee.sock")
	// We want to return format "protocol:address" so remove leading colon for TCP
	addr := s.listenAddr
	if s.protocol == "tcp" && strings.HasPrefix(addr, ":") {
		addr = addr[1:] // Remove leading colon
	}
	return fmt.Sprintf("%s:%s", s.protocol, addr)
}

func (s *Server) cleanup() {
	s.server.GracefulStop()
}

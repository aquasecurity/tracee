package grpc

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
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
	return &Server{listener: nil, protocol: protocol, listenAddr: listenAddr}
}

func (s *Server) Start(ctx context.Context, t *tracee.Tracee, e *engine.Engine) {
	// Create listener when starting
	lis, err := net.Listen(s.protocol, s.listenAddr)
	if err != nil {
		logger.Errorw("Failed to start GRPC server", "protocol", s.protocol, "address", s.listenAddr, "error", err)
		return
	}

	if s.protocol == "tcp" {
		host, _, _ := net.SplitHostPort(s.listenAddr)
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			logger.Warnw("gRPC server binding to non-loopback address without TLS or authentication",
				"address", s.listenAddr,
				"hint", "ensure network-level controls (firewall, NetworkPolicy) restrict access",
			)
		}
	}

	// Set restrictive permissions on Unix socket using fd-based Fchmod
	// to avoid TOCTOU between Listen and Chmod.
	if s.protocol == "unix" {
		if uc, ok := lis.(*net.UnixListener); ok {
			raw, rawErr := uc.SyscallConn()
			if rawErr != nil {
				logger.Errorw("Failed to get syscall conn for Unix socket", "path", s.listenAddr, "error", rawErr)
				_ = lis.Close()
				return
			}
			var chmodErr error
			if ctrlErr := raw.Control(func(fd uintptr) {
				chmodErr = unix.Fchmod(int(fd), 0600)
			}); ctrlErr != nil {
				logger.Errorw("Failed to access Unix socket fd", "path", s.listenAddr, "error", ctrlErr)
				_ = lis.Close()
				return
			}
			if chmodErr != nil {
				logger.Errorw("Failed to set permissions on Unix socket. This may leave the socket with insecure permissions and allow unauthorized access.", "path", s.listenAddr, "error", chmodErr)
				_ = lis.Close()
				return
			}
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

	// Tracee might be nil in unit tests
	if t != nil {
		t.RegisterE2eGrpcServices(grpcServer)
	}

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
	return fmt.Sprintf("%s:%s", s.protocol, s.listenAddr)
}

func (s *Server) cleanup() {
	s.server.GracefulStop()
}

package client

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
)

const (
	DefaultSocket = "/var/run/tracee.sock"
)

type Server struct {
	Addr             string
	conn             *grpc.ClientConn
	diagnosticClient pb.DiagnosticServiceClient
	serviceClient    pb.TraceeServiceClient
}

func NewClient(addr string) (*Server, error) {
	return &Server{
		Addr: addr,
	}, nil
}
func (s *Server) Connect() error {
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	conn, err := grpc.NewClient("unix://"+s.Addr, opts...)
	if err != nil {
		return err
	}
	s.conn = conn
	s.diagnosticClient = pb.NewDiagnosticServiceClient(s.conn)
	s.serviceClient = pb.NewTraceeServiceClient(s.conn)
	return nil
}
func (s *Server) Close() error {
	return s.conn.Close()
}

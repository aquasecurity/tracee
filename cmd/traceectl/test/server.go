package test

import (
	"fmt"
	"log"
	"net"
	"os"
)

const DefaultSocket = "/tmp/tracee.sock"

type Server struct {
	addr     string
	listener net.Listener
}

func SetupMockSocket() (*Server, error) {
	listener, err := net.Listen("unix", DefaultSocket)
	if err != nil {
		return nil, err
	}
	return &Server{
		addr:     DefaultSocket,
		listener: listener,
	}, nil
}

func (s *Server) TeardownMockSocket() error {
	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			return fmt.Errorf("failed to close mock socket: %w", err) // Wrap the error
		}
	}
	// Check if the socket file still exists and remove it
	if _, err := os.Stat(DefaultSocket); err == nil {
		if err := os.Remove(DefaultSocket); err != nil {
			log.Printf("Warning: failed to remove mock socket file: %v", err)
		}
	}
	return nil
}

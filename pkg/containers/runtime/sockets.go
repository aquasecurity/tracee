package runtime

import (
	"fmt"
	"os"
)

// Sockets represent existing container runtime connections
type Sockets struct {
	sockets map[RuntimeId]string
}

// Register attempts to associate a file path with a container runtime, if the path doens't exist registration will fail
func (s *Sockets) Register(runtime RuntimeId, socket string) error {
	if s.sockets == nil {
		s.sockets = make(map[RuntimeId]string)
	}

	_, err := os.Stat(socket)
	if err != nil {
		return fmt.Errorf("failed to register runtime socket %v", err)
	}
	s.sockets[runtime] = socket
	return nil
}

// Supports check if the runtime was registered in the Sockets struct
func (s *Sockets) Supports(runtime RuntimeId) bool {
	return s.sockets != nil && s.sockets[runtime] != ""
}

// Socket returns the relevant socket for the runtime if one was registered
func (s *Sockets) Socket(runtime RuntimeId) string {
	if s.sockets == nil {
		return ""
	}
	return s.sockets[runtime]
}

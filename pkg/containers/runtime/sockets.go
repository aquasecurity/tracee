package runtime

import (
	"os"

	"github.com/aquasecurity/tracee/pkg/errfmt"
)

// Sockets represent existing container runtime connections
type Sockets struct {
	sockets map[RuntimeId]string
}

// Register attempts to associate a file path with a container runtime, if the path doesn't exist registration will fail
func (s *Sockets) Register(runtime RuntimeId, socket string) error {
	if s.sockets == nil {
		s.sockets = make(map[RuntimeId]string)
	}

	_, err := os.Stat(socket)
	if err != nil {
		return errfmt.Errorf("failed to register runtime socket %v", err)
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

// check default paths for all supported container runtimes and aggregate them
func Autodiscover(onRegisterFail func(err error, runtime RuntimeId, socket string)) Sockets {
	register := func(sockets *Sockets, runtime RuntimeId, socket string) {
		err := sockets.Register(runtime, socket)
		if err != nil {
			onRegisterFail(err, runtime, socket)
		}
	}
	sockets := Sockets{}
	const (
		defaultContainerd = "/var/run/containerd/containerd.sock"
		defaultDocker     = "/var/run/docker.sock"
		defaultCrio       = "/var/run/crio/crio.sock"
		defaultPodman     = "/var/run/podman/podman.sock"
	)

	register(&sockets, Containerd, defaultContainerd)
	register(&sockets, Docker, defaultDocker)
	register(&sockets, Crio, defaultCrio)
	register(&sockets, Podman, defaultPodman)

	return sockets
}

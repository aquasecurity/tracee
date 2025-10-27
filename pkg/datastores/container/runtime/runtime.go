package runtime

import (
	"context"
)

// These labels are injected by kubelet on container creation, we can use them to gather additional data in a k8s context
const (
	PodNameLabel                 = "io.kubernetes.pod.name"
	PodNamespaceLabel            = "io.kubernetes.pod.namespace"
	PodUIDLabel                  = "io.kubernetes.pod.uid"
	ContainerNameLabel           = "io.kubernetes.container.name"
	ContainerTypeDockerLabel     = "io.kubernetes.docker.type"
	ContainerTypeContainerdLabel = "io.cri-containerd.kind"
	ContainerTypeCrioAnnotation  = "io.kubernetes.cri-o.ContainerType"
)

type EnrichResult struct {
	/* CONTAINER RESULTS */
	ContName    string
	Image       string
	ImageDigest string
	/* POD RESULTS */
	PodName   string
	Namespace string
	UID       string
	Sandbox   bool
}

type ContainerEnricher interface {
	Get(ctx context.Context, containerId string) (EnrichResult, error)
	Close() error
}

// Represents the internal ID of a container runtime
type RuntimeId int

const (
	Unknown RuntimeId = iota
	Docker
	Containerd
	Crio
	Podman
	Garden
)

var runtimeStringMap = map[RuntimeId]string{
	Unknown:    "unknown",
	Docker:     "docker",
	Containerd: "containerd",
	Crio:       "crio",
	Podman:     "podman",
	Garden:     "garden", // there is no enricher (yet ?) for garden
}

func (runtime RuntimeId) String() string {
	return runtimeStringMap[runtime]
}

func FromString(str string) RuntimeId {
	switch str {
	case "docker":
		return Docker
	case "crio":
		return Crio
	case "cri-o":
		return Crio
	case "podman":
		return Podman
	case "containerd":
		return Containerd
	case "garden":
		return Garden

	default:
		return Unknown
	}
}

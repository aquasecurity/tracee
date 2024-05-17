package runtime

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	cri "k8s.io/cri-api/pkg/apis/runtime/v1"

	"github.com/aquasecurity/tracee/pkg/errfmt"
)

type crioEnricher struct {
	client cri.RuntimeServiceClient
}

func CrioEnricher(socket string) (ContainerEnricher, error) {
	unixSocket := "unix://" + strings.TrimPrefix(socket, "unix://")
	conn, err := grpc.NewClient(unixSocket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, errfmt.WrapError(err)
	}
	client := cri.NewRuntimeServiceClient(conn)

	enricher := &crioEnricher{
		client: client,
	}

	return enricher, nil
}

func (e *crioEnricher) Get(ctx context.Context, containerId string) (ContainerMetadata, error) {
	metadata := ContainerMetadata{
		ContainerId: containerId,
	}
	resp, err := e.client.ContainerStatus(context.Background(), &cri.ContainerStatusRequest{
		ContainerId: containerId,
		Verbose:     true,
	})
	if err != nil {
		return metadata, errfmt.WrapError(err)
	}

	// if in k8s we can extract pod info from labels
	labels := resp.Status.Labels
	if labels != nil {
		metadata.Pod = PodMetadata{
			Name:      labels[PodNameLabel],
			Namespace: labels[PodNamespaceLabel],
			UID:       labels[PodUIDLabel],
		}
	}
	annotations := resp.Status.Annotations
	if annotations != nil {
		metadata.Pod.Sandbox = e.isSandbox(annotations)
	}
	metadata.Name = resp.Status.Metadata.Name
	metadata.Image = resp.Status.Image.Image
	metadata.ImageDigest = resp.Status.ImageRef

	return metadata, nil
}

func (e *crioEnricher) isSandbox(annotations map[string]string) bool {
	return annotations[ContainerTypeCrioAnnotation] == "sandbox"
}

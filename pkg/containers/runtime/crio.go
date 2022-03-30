package runtime

import (
	"context"
	"strings"

	cri "github.com/kubernetes/cri-api/pkg/apis/runtime/v1alpha2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type crioEnricher struct {
	client cri.RuntimeServiceClient
}

func CrioEnricher(socket string) (ContainerEnricher, error) {
	unixSocket := "unix://" + strings.TrimPrefix(socket, "unix://")
	conn, err := grpc.Dial(unixSocket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	client := cri.NewRuntimeServiceClient(conn)

	enricher := &crioEnricher{
		client: client,
	}

	return enricher, nil
}

func (e *crioEnricher) Get(containerId string, ctx context.Context) (ContainerMetadata, error) {
	metadata := ContainerMetadata{
		ContainerId: containerId,
	}
	resp, err := e.client.ContainerStatus(context.Background(), &cri.ContainerStatusRequest{
		ContainerId: containerId,
		Verbose:     true,
	})
	if err != nil {
		return metadata, err
	}

	//if in k8s we can extract pod info from labels
	labels := resp.Status.Labels
	if labels != nil {
		metadata.Pod = PodMetadata{
			Name:      labels[PodNameLabel],
			Namespace: labels[PodNamespaceLabel],
			UID:       labels[PodUIDLabel],
		}
	}
	metadata.Name = resp.Status.Metadata.Name
	metadata.Image = resp.Status.Image.Image

	return metadata, nil
}

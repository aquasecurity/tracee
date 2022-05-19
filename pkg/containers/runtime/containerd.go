package runtime

import (
	"context"
	"fmt"
	"strings"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/namespaces"
	cri "github.com/kubernetes/cri-api/pkg/apis/runtime/v1alpha2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type containerdEnricher struct {
	containers containers.Store
	images     cri.ImageServiceClient
	namespaces namespaces.Store
}

func ContainerdEnricher(socket string) (ContainerEnricher, error) {
	enricher := containerdEnricher{}
	unixSocket := "unix://" + strings.TrimPrefix(socket, "unix://")

	client, err := containerd.New(socket)
	if err != nil {
		return nil, err
	}

	conn, err := grpc.Dial(unixSocket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		client.Close()
		return nil, err
	}

	enricher.images = cri.NewImageServiceClient(conn)
	enricher.containers = client.ContainerService()
	enricher.namespaces = client.NamespaceService()

	return &enricher, nil
}

func (e *containerdEnricher) Get(containerId string, ctx context.Context) (ContainerMetadata, error) {
	metadata := ContainerMetadata{
		ContainerId: containerId,
	}
	nsList, err := e.namespaces.List(ctx)
	if err != nil {
		return metadata, fmt.Errorf("failed to fetch namespaces %s", err.Error())
	}
	for _, namespace := range nsList {
		nsCtx := namespaces.WithNamespace(ctx, namespace)
		container, err := e.containers.Get(nsCtx, containerId)
		if err != nil {
			//if containers is not in current namespace, search the next one
			continue
		} else {
			imageName := container.Image
			image := container.Image
			//container may not have image name as id, if so fetch from the sha256 id
			if strings.HasPrefix(image, "sha256:") {
				imageInfo, err := e.images.ImageStatus(ctx, &cri.ImageStatusRequest{
					Image: &cri.ImageSpec{
						Image: strings.TrimPrefix(image, "sha256:"),
					},
				})
				if err != nil {
					imageName = image
				} else {
					if len(imageInfo.Image.RepoTags) > 0 {
						imageName = imageInfo.Image.RepoTags[0]
					}
				}
			}

			//if in k8s we can extract pod info from labels
			if container.Labels != nil {
				labels := container.Labels

				metadata.Pod = PodMetadata{
					Name:      labels[PodNameLabel],
					Namespace: labels[PodNamespaceLabel],
					UID:       labels[PodUIDLabel],
				}

				//containerd containers normally have no names unless set from k8s
				metadata.Name = labels[ContainerNameLabel]
			}
			metadata.Image = imageName

			return metadata, nil
		}
	}

	return metadata, fmt.Errorf("failed to find container in any namespace")
}

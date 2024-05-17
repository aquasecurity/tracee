package runtime

import (
	"context"
	"strings"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/namespaces"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	cri "k8s.io/cri-api/pkg/apis/runtime/v1"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
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
		return nil, errfmt.WrapError(err)
	}

	conn, err := grpc.NewClient(unixSocket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		if errC := client.Close(); errC != nil {
			logger.Errorw("Closing containerd connection", "error", errC)
		}
		return nil, errfmt.WrapError(err)
	}

	enricher.images = cri.NewImageServiceClient(conn)
	enricher.containers = client.ContainerService()
	enricher.namespaces = client.NamespaceService()

	return &enricher, nil
}

func (e *containerdEnricher) Get(ctx context.Context, containerId string) (ContainerMetadata, error) {
	metadata := ContainerMetadata{
		ContainerId: containerId,
	}
	nsList, err := e.namespaces.List(ctx)
	if err != nil {
		return metadata, errfmt.Errorf("failed to fetch namespaces %s", err.Error())
	}
	for _, namespace := range nsList {
		nsCtx := namespaces.WithNamespace(ctx, namespace)

		// if containers is not in current namespace, search the next one
		container, err := e.containers.Get(nsCtx, containerId)
		if err != nil {
			continue
		}

		imageName := container.Image
		imageDigest := container.Image
		image := container.Image
		// container may not have image name as id, if so fetch from the sha256 id
		if strings.HasPrefix(image, "sha256:") {
			imageInfo, err := e.images.ImageStatus(ctx, &cri.ImageStatusRequest{
				Image: &cri.ImageSpec{
					Image: strings.TrimPrefix(image, "sha256:"),
				},
			})
			if err != nil {
				imageName = image
				imageDigest = image
			} else {
				if len(imageInfo.Image.RepoTags) > 0 {
					imageName = imageInfo.Image.RepoTags[0]
				}
				if len(imageInfo.Image.RepoDigests) > 0 {
					imageDigest = imageInfo.Image.RepoTags[0]
				}
			}
		}

		// if in k8s we can extract pod info from labels
		if container.Labels != nil {
			labels := container.Labels

			metadata.Pod = PodMetadata{
				Name:      labels[PodNameLabel],
				Namespace: labels[PodNamespaceLabel],
				UID:       labels[PodUIDLabel],
				Sandbox:   e.isSandbox(labels),
			}

			// containerd containers normally have no names unless set from k8s
			metadata.Name = labels[ContainerNameLabel]
		}
		metadata.Image = imageName
		metadata.ImageDigest = imageDigest

		return metadata, nil
	}

	return metadata, errfmt.Errorf("failed to find container in any namespace")
}

func (e *containerdEnricher) isSandbox(labels map[string]string) bool {
	return labels[ContainerTypeContainerdLabel] == "sandbox"
}

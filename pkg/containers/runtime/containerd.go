package runtime

import (
	"context"
	"strings"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/namespaces"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	cri "k8s.io/cri-api/pkg/apis/runtime/v1"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
)

type containerdEnricher struct {
	containers containers.Store
	images     images.Store
	images_cri cri.ImageServiceClient
	namespaces namespaces.Store
}

func ContainerdEnricher(socket string) (ContainerEnricher, error) {
	enricher := containerdEnricher{}

	// avoid duplicate unix:// prefix
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

	enricher.images_cri = cri.NewImageServiceClient(conn)
	enricher.containers = client.ContainerService()
	enricher.namespaces = client.NamespaceService()
	enricher.images = client.ImageService()

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
		// always query with namespace applied
		nsCtx := namespaces.WithNamespace(ctx, namespace)

		// if containers is not in current namespace, search the next one
		container, err := e.containers.Get(nsCtx, containerId)
		if err != nil {
			continue
		}

		image := container.Image
		var imageName, imageDigest string

		i, d, err := e.getImageInfoStore(nsCtx, image)
		if err != nil {
			// try using cri directly
			i, d, err2 := e.getImageInfoCri(nsCtx, image)
			if err2 != nil {
				logger.Debugw("failed to extract image digest from containerd service and cri", "err", err, "err_cri", err2)
				imageName = image
				imageDigest = image
			} else {
				imageName = i
				imageDigest = d
			}
		} else {
			imageName = i
			imageDigest = d
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

// revive:disable:confusing-results

func (e *containerdEnricher) getImageInfoStore(ctx context.Context, image string) (string, string, error) {
	r, err := e.images.Get(ctx, image)
	if err != nil {
		return "", "", err
	}

	i := r.Name
	d := r.Target.Digest.String()
	return i, d, nil
}

// revive:enable:confusing-results

// revive:disable:confusing-results

func (e *containerdEnricher) getImageInfoCri(ctx context.Context, image string) (string, string, error) {
	var imageName, imageDigest string
	var imageInfo *cri.ImageStatusResponse
	var err error

	if strings.HasPrefix(image, "sha256:") {
		// container may not have image name as id, if so fetch from the sha256 id
		imageInfo, err = e.images_cri.ImageStatus(ctx, &cri.ImageStatusRequest{
			Image: &cri.ImageSpec{
				Image: strings.TrimPrefix(image, "sha256:"),
			},
		})
	} else {
		// else query directly
		imageInfo, err = e.images_cri.ImageStatus(ctx, &cri.ImageStatusRequest{
			Image: &cri.ImageSpec{
				UserSpecifiedImage: image,
			},
		})
	}
	if err != nil {
		return "", "", err
	} else if imageInfo.Image == nil {
		// image was nil - no image found
		return "", "", errfmt.Errorf("no image info found in containerd cri (query: %s)", image)
	}

	// image found - extract name and digest
	if len(imageInfo.Image.RepoTags) > 0 {
		imageName = imageInfo.Image.RepoTags[0]
	}
	if len(imageInfo.Image.RepoDigests) > 0 {
		imageDigest = imageInfo.Image.RepoDigests[0]
	}
	return imageName, imageDigest, nil
}

// revive:enable:confusing-results

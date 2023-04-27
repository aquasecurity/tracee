package runtime

import (
	"context"
	"strings"

	docker "github.com/docker/docker/client"

	"github.com/aquasecurity/tracee/pkg/errfmt"
)

type dockerEnricher struct {
	client *docker.Client
}

func DockerEnricher(socket string) (ContainerEnricher, error) {
	unixSocket := "unix://" + strings.TrimPrefix(socket, "unix://")
	cli, err := docker.NewClientWithOpts(docker.WithHost(unixSocket), docker.WithAPIVersionNegotiation())
	if err != nil {
		return nil, errfmt.WrapError(err)
	}

	enricher := &dockerEnricher{}
	enricher.client = cli

	return enricher, nil
}

func (e *dockerEnricher) Get(ctx context.Context, containerId string) (ContainerMetadata, error) {
	metadata := ContainerMetadata{
		ContainerId: containerId,
	}
	resp, err := e.client.ContainerInspect(ctx, containerId)
	if err != nil {
		return metadata, errfmt.WrapError(err)
	}
	container := (*resp.ContainerJSONBase)
	metadata.Name = container.Name

	// Docker prefixes a '/' token to local containers.
	// This can cause some confusion so we remove it if relevant.
	if strings.HasPrefix(metadata.Name, "/") {
		metadata.Name = container.Name[1:]
	}

	// get initial image name from docker's container config
	if resp.Config != nil {
		metadata.Image = resp.Config.Image

		// if in k8s extract pod data from the labels
		if resp.Config.Labels != nil {
			labels := resp.Config.Labels
			metadata.Pod = PodMetadata{
				Name:      labels[PodNameLabel],
				Namespace: labels[PodNamespaceLabel],
				UID:       labels[PodUIDLabel],
				Sandbox:   e.isSandbox(labels),
			}
		}
	}

	// attempt to get image name from registry (image from config usually has tag as sha/no tag at all)
	imageId := container.Image
	image, _, err := e.client.ImageInspectWithRaw(ctx, imageId)
	if err != nil {
		// if we can't fetch the image or image has no name, return the metadata with the image found in config
		return metadata, nil
	}

	if len(image.RepoTags) == 0 {
		return metadata, nil
	}
	imageName := image.RepoTags[0]
	metadata.Image = imageName

	if len(image.RepoDigests) == 0 {
		return metadata, nil
	}
	metadata.ImageDigest = image.RepoDigests[0]

	return metadata, nil
}

func (e *dockerEnricher) isSandbox(labels map[string]string) bool {
	return labels[ContainerTypeDockerLabel] == "sandbox"
}

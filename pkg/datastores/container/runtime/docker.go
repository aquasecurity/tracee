package runtime

import (
	"context"
	"strings"

	docker "github.com/moby/moby/client"

	"github.com/aquasecurity/tracee/common/errfmt"
)

type dockerEnricher struct {
	client *docker.Client
}

func DockerEnricher(socket string) (ContainerEnricher, error) {
	unixSocket := "unix://" + strings.TrimPrefix(socket, "unix://")
	// New enables API version negotiation by default.
	cli, err := docker.New(docker.WithHost(unixSocket))
	if err != nil {
		return nil, errfmt.WrapError(err)
	}

	enricher := &dockerEnricher{}
	enricher.client = cli

	return enricher, nil
}

func (e *dockerEnricher) Get(ctx context.Context, containerId string) (EnrichResult, error) {
	res := EnrichResult{}
	resp, err := e.client.ContainerInspect(ctx, containerId, docker.ContainerInspectOptions{})
	if err != nil {
		return res, errfmt.WrapError(err)
	}
	container := resp.Container

	// Docker prefixes a '/' token to local containers.
	// This can cause some confusion so we remove it if relevant.
	res.ContName = strings.TrimPrefix(container.Name, "/")

	// get initial image name from docker's container config
	if container.Config != nil {
		res.Image = container.Config.Image

		// if in k8s extract pod data from the labels
		if container.Config.Labels != nil {
			labels := container.Config.Labels
			res.PodName = labels[PodNameLabel]
			res.Namespace = labels[PodNamespaceLabel]
			res.UID = labels[PodUIDLabel]
			res.Sandbox = e.isSandbox(labels)
		}
	}

	// attempt to get image name from registry (image from config usually has tag as sha/no tag at all)
	imageId := container.Image
	image, err := e.client.ImageInspect(ctx, imageId)
	if err != nil {
		// if we can't fetch the image or image has no name, return the metadata with the image found in config
		return res, nil
	}

	if len(image.RepoTags) == 0 {
		return res, nil
	}
	imageName := image.RepoTags[0]
	res.Image = imageName

	if len(image.RepoDigests) == 0 {
		return res, nil
	}
	res.ImageDigest = image.RepoDigests[0]

	return res, nil
}

func (e *dockerEnricher) isSandbox(labels map[string]string) bool {
	return labels[ContainerTypeDockerLabel] == "sandbox"
}

func (e *dockerEnricher) Close() error {
	return e.client.Close()
}

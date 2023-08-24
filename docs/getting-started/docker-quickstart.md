# Docker Quickstart

You can easily start experimenting with Tracee using the Docker image as follows:

```console
docker run \
  --name tracee --rm -it \
  --pid=host --cgroupns=host --privileged \
  -v /etc/os-release:/etc/os-release-host:ro \
  aquasec/tracee:latest
```

To learn how to install Tracee in a production environment, [check out the Kubernetes guide](./kubernetes-quickstart).

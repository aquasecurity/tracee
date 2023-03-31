# Tracee Events Container Enrichment

Tracee is capable of **extracting information about running containers**. It
does that by tracking container namespaces creation kernel events and enriching
those events by communicating with the relevant container's runtime and SDK.

!!! Experimental Warning
    This feature is experimental and should be explicitly enabled in
    **tracee**, by using the `--container` flag OR, if running tracee
    container image, setting the `CONTAINERS_ENRICHMENT` environment flag (see
    example bellow).

1. Running **tracee** manually

    If running tracee directly (not in a container), it will automatically
    search for known supported runtimes in their socket's default locations.

2. Running **tracee** using a docker container

    When running tracee from a container, the runtime sockets must be manually
    mounted in order for the enrichment features to work.

    Using containerd as our runtime for example, this can be done by running
    tracee like:
    
    ```console
    docker run \
        --name tracee --rm -it \
        --pid=host --cgroupns=host --privileged \
        -v /etc/os-release:/etc/os-release-host:ro \
        -v /var/run/containerd:/var/run/containerd \
        -e LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host \
        -e CONTAINERS_ENRICHMENT=1 \
        aquasec/tracee:{{ git.tag }}
    ```

    Most container runtimes have their sockets installed by default in
    `/var/run`. If your system includes multiple container runtimes, tracee can
    track them all, however one should mount either all their runtime sockets
    or `/var/run` in it's entirety to do so.

## Supported Container Runtime Engines

Currently, tracee will look in the following paths for auto-discovering the listed runtimes:

1. Docker:     `/var/run/docker.sock`

2. Containerd: `/var/run/containerd/containerd.sock`

3. CRI-O:      `/var/run/crio/crio.sock`

4. Podman:     `/var/run/podman/podman.sock`

!!! Tip
    **Nested environments** are somewhat tricky with this feature as evidenced
    by the docker mounting instructions. Tracee does not auto-discover this
    nesting and so sockets must be appropriately mounted and set up for tracee
    to enrich all containers correctly.

## Viewing enrichment output

As a user, when container enrichment is enabled the event output will include enriched fields in these cases:

1. Running **tracee** with a json format will include all container enriched fields

    ```console
    docker run \
        --name tracee --rm -it \
        --pid=host --cgroupns=host --privileged \
        -v /etc/os-release:/etc/os-release-host:ro \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -e LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host \
        aquasec/tracee:{{ git.tag }} \
        trace --output json --containers
    ```

2. Running in container filtering mode and with enrichment enabled will add the image name to the table printer

    ```console
    docker run \
        --name tracee --rm -it \
        --pid=host --cgroupns=host --privileged \
        -v /etc/os-release:/etc/os-release-host:ro \
        -v /var/run/containerd:/var/run/containerd \
        -e LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host \
        aquasec/tracee:{{ git.tag }} \
        trace --filter container --containers
    ```

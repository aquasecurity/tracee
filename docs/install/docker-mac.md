# Docker for Mac

Docker for Mac does not come with Kernel headers.
You need to do the following to make Tracee work:

1. Identify your docker version:
   ```
   dockerver=$(docker version | grep  Version | head -n 1 | cut -d ':' -f 2 | xargs)
   ```
2. Run a container with Docker CLI, while mounting to the host path:
   ```
   docker run -it -v /:/host -v /var/run/docker.sock:/var/run/docker.sock docker:$dockerver /bin/sh
   ```
3. Get the Kernel Header files from the linuxkit Docker image and copy it to the host /usr/src path:
   ```
   mkdir /host/kheader
   cd /host/kheader
   linux_version="${VERSION:-$(uname -r | cut -d - -f 1)}"
   docker pull "linuxkit/kernel:$linux_version"
   docker save "linuxkit/kernel:$linux_version" > "linuxkit.tar"
   tar -xf "linuxkit.tar"
   layertar=$(find . -name layer.tar)
   tar -xf "$layertar"
   tar -xf "kernel-dev.tar" --directory /host/
   ```
4. You can now run Tracee on your Docker for Mac
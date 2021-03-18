```bash
docker run -it --name tracee --rm --privileged --pid=host -v /lib/modules/:/lib/modules/:ro -v /usr/src:/usr/src:ro -v /tmp/tracee:/tmp/tracee aquasec/tracee:latest trace
```

> Note: You may need to change the volume mounts for the kernel headers based on your setup. See [Linux Headers](../options/#linux-headers) section for info.

This will run Tracee-eBPF with no arguments, which defaults to collecting a useful default set of events from all processes and print them in a table to standard output.

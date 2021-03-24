## Quickstart with Docker

```bash
docker run --name tracee --rm --privileged -v /lib/modules/:/lib/modules/:ro -v /usr/src:/usr/src:ro -v /tmp/tracee:/tmp/tracee aquasec/tracee:latest
```

> Note: You may need to change the volume mounts for the kernel headers based on your setup. See [Linux Headers](../options/#linux-headers) section for info.

This will run Tracee with no arguments, which defaults to loading the default set of rules (see below), and to report detections on standard output (can be customized).
In order to simulate a suspicious behavior, you can run `strace ls` in another terminal, which will trigger the "Anti-Debugging" signature, which is loaded by default.


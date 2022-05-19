# Integrations

When a detection is made by any of the signatures, it will always be printed to stdout. You can customize the output format using a [go template](https://golang.org/pkg/text/template/):

```bash
tracee-rules --output-template /path/to/my.tmpl
```

In addition, Tracee can notify a web service when a detection is made using a custom webhook:

```bash
tracee-rules --webhook http://my.webhook/endpoint \
  --webhook-template /path/to/my.tmpl \
  --webhook-content-type application/json
```

## Included Go templates

The following Go templates are included in the Tracee container image and are available for use under the `/tracee/templates/` directory in the container:

| File name          | Description                            | Content-Type       | Source                                                                                                            |
|--------------------|----------------------------------------|--------------------|-------------------------------------------------------------------------------------------------------------------|
| falcosidekick.tmpl | For compatibility with [falcosidekick] | `application/json` | [source](https://github.com/aquasecurity/tracee/blob/{{ git.tag }}/cmd/tracee-rules/templates/falcosidekick.tmpl) |
| rawjson.tmpl       | Dumps the Finding object as raw JSON   | `application/json` | [source](https://github.com/aquasecurity/tracee/blob/{{ git.tag }}/cmd/tracee-rules/templates/rawjson.tmpl)       |

## Go Template Authoring

When authoring a Go template for either stdout or webhook, you have Tracee's `types.Finding` struct as the data source:

```go
//Finding is the main output of a signature. It represents a match result for the signature business logic
type Finding struct {
	SigMetadata SignatureMetadata //information about the signature that made the detection
	Context     Event //the raw event that triggered the detection
	Data        map[string]interface{} //detection specific information
}
```

The Go template can utilize helper functions from [Sprig].

For example templates, see [tracee/cmd/tracee-rules/templates].

## Prometheus

Tracee is enabled for prometheus scraping by default. Scraping can be done through the following URLs:1
1. `tracee-ebpf` can be scraped through `:3366/metrics`
2. `tracee-rules` can be scraped through `:4466/metrics`

The metrics addresses can be changed through running with the `metrics` and `metrics-addr` in the cli.

## Examples

### Raw JSON stdout

The following example configures Tracee to output detections to stdout as raw JSON:

```bash
docker run --rm -it --privileged --pid=host --cgroupns=host \
  -v /lib/modules/:/lib/modules/:ro \
  -v /usr/src:/usr/src:ro \
  -v /tmp/tracee:/tmp/tracee \
  aquasec/tracee:{{ git.tag[1:] }} \
  --output-template /tracee/templates/rawjson.tmpl
```

### falcosidekick webhook

[falcosidekick] is a useful webhook server that can be configured to connect to various "outputs" such as: Slack, Mattermost, Teams, Datadog, Prometheus, StatsD, Email, Elasticsearch, Loki, PagerDuty, OpsGenie, and many more.

To use Tracee with falcosidekick:

1. Obtain connection credentials to the system you want to integrate with.
    1. Consult the system's documentation and look for how to configure an incoming webhook.
2. Start the falcosidekick container, configured with the obtained output credentials:
    1. See the [falcosidekick Readme](https://github.com/falcosecurity/falcosidekick) for full documentation.
3. Start Tracee while configuring it to post detections to the falcosidekick endpoint.
    1. If using Docker, you can use the simple [link](https://docs.docker.com/network/links/) flag to allow the containers to communicate
    2. Use the webhook flag to point to the falcosidekick container's endpoint
    3. Tracee ships with a built-in template for falcosidekick


```bash
# Start falcosidekick configured to post to Slack
docker run --name falcosidekick -p 2801:2801 \
  -e SLACK_WEBHOOKURL=https://hooks.slack.com/services/XXX/YYY/ZZZ \
  falcosecurity/falcosidekick

# Start Tracee, linking it to the falcosidekick container, and configuring it to call it on detections
docker run --name tracee --rm -it --privileged --pid=host --cgroupns=host \
  -v /lib/modules/:/lib/modules/:ro \
  -v /usr/src:/usr/src:ro \
  -v /tmp/tracee:/tmp/tracee \
  --link falcosidekick aquasec/tracee:{{ git.tag[1:] }} \
  --webhook-template /tracee/templates/falcosidekick.tmpl \
  --webhook-content-type application/json \
  --webhook http://FALCOSIDEKICK:2801
```

[Sprig]: http://masterminds.github.io/sprig/
[tracee/cmd/tracee-rules/templates]: https://github.com/aquasecurity/tracee/tree/{{ git.tag }}/cmd/tracee-rules/templates
[falcosidekick]: https://github.com/falcosecurity/falcosidekick

# Container Runtimes

Tracee is capable of extracting information on running containers on your system during runtime through tracking created cgroups in kernel and
can further enrich the container events from data queried by communicating with the relevant container's runtime and SDK from userspace.
If running tracer-ebpf directly from binary, it will automatically search for known supported runtimes in their default socket's locations.
However, when running tracee from a container, the runtime sockets must be manually mounted in order for the enrichment features to work.
Using containerd as our runtime for example, this can be done by running tracee like so:
```shell
   docker run \
     --name tracee --rm -it \
     --pid=host --cgroupns=host --privileged \
     -v /etc/os-release:/etc/os-release-host:ro \
     -v /var/run/containerd:/var/run/containerd
     -e LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host \
     aquasec/tracee:latest
```

Most container runtimes have their sockets installed by default in `/var/run` so if your system includes multiple container runtimes, tracee can track
them all, however one should then mount either all their runtime sockets or `/var/run` in it's entirety.

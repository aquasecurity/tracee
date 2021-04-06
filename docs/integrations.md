# Integrations

When a detection is made by any of the signatures, it will always be printed to stdout. You can customize the output format using a [go template](https://golang.org/pkg/text/template/):

```bash
tracee-rules --output-template /path/to/my.tmpl
```

In addition, Tracee can notify a web service when a detection is made using a custom webhook:

```bash
tracee-rules --webhook http://my.webhook/endpoint --webhook-template /path/to/my.tmpl --webhook-content-type application/json
```

## Included Go templates

The following go templates are included in the Tracee container image and are available for use under the `/tracee/templates/` directory in the container:

File name | Description | Content-Type | Source
--- | --- | --- | ---
falcosidekick.tmpl | For compatibility with [falcosidekick](https://github.com/falcosecurity/falcosidekick) | `application/json` | [source](https://github.com/aquasecurity/tracee/blob/main/tracee-rules/templates/falcosidekick.tmpl)
rawjson.tmpl | Dumps the Finding object as raw JSON | `application/json` | [source](https://github.com/aquasecurity/tracee/blob/main/tracee-rules/templates/rawjson.tmpl)


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

The Go template can utilize helper functions from [Sprig](http://masterminds.github.io/sprig/).

For example templates, see [tracee/tracee-rules/templates](https://github.com/aquasecurity/tracee/tree/main/tracee-rules/templates).

## Examples

### Raw JSON stdout

The following example configures Tracee to output detections to stdout as raw JSON:

```bash
docker run --rm --privileged --pid=host -v /lib/modules/:/lib/modules/:ro -v /usr/src:/usr/src:ro -v /tmp/tracee:/tmp/tracee -it aquasec/tracee --output-template /tracee/templates/rawjson.tmpl
```

### falcosidekick webhook

[falcosidekick](https://github.com/falcosecurity/falcosidekick) is a useful webhook server that can be configured to connect to various "outputs" such as: Slack, Mattermost, Teams, Datadog, Prometheus, StatsD, Email, Elasticsearch, Loki, PagerDuty, OpsGenie, and many more.

To use Tracee with falcosidekick:

1. Obtain connection credentials to the system you want to integrate with.
    1. Consult the system's documentation and look for how to configure an incoming webhook.
2. Start the falcosidekick container, configured with the obtained output credentials:
    1. See the the [falcosidekick Readme](https://github.com/falcosecurity/falcosidekick) for full documentation.
3. Start Tracee while configuring it to post detections to the falcosidekick endpoint.
    1. If using Docker, you can use the simple [link](https://docs.docker.com/network/links/) flag to allow the containers to communicate
	  2. Use the webhook flag to point to the falcosidekick container's endpoint
	  3. Tracee ships with a built-in template for falcosidekick


```bash
# Start falcosidekick configured to post to Slack
docker run --name falcosidekick -p 2801:2801 -e SLACK_WEBHOOKURL=https://hooks.slack.com/services/XXX/YYY/ZZZ falcosecurity/falcosidekick

# Start Tracee, linking it to the falcosidekick container, and configuring it to call it on detections
docker run --rm --privileged --pid=host -v /lib/modules/:/lib/modules/:ro -v /usr/src:/usr/src:ro -v /tmp/tracee:/tmp/tracee -it --link falcosidekick aquasec/tracee --webhook-template /tracee/templates/falcosidekick.tmpl --webhook-content-type application/json --webhook http://FALCOSIDEKICK:2801
```

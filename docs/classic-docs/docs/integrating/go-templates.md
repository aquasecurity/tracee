# Detections: Output Format

## Configuring

When a detection is made by any of the loaded signatures, it will always be
printed to stdout. You can customize this output format using a [go template].

```bash
$ ./dist/tracee-rules --output-template /path/to/my.tmpl
```

[go template]: https://golang.org/pkg/text/template

!!! Go-templates Note

    The following Go templates are included in the Tracee container image and are
    available for use under the `/tracee/templates/` directory in the container:
    
    | File name          | Description                            | Content-Type       | Source                                                                                                            |
    |--------------------|----------------------------------------|--------------------|-------------------------------------------------------------------------------------------------------------------|
    | rawjson.tmpl       | Dumps the Finding object as raw JSON   | `application/json` | [source](https://github.com/aquasecurity/tracee/blob/{{ git.tag }}/cmd/tracee-rules/templates/rawjson.tmpl)       |

1. Basic Example: **Raw JSON** stdout

    The following example configures Tracee to output detections to stdout as raw JSON:

    ```text
    $ docker run \
        --name tracee --rm -it \
        --pid=host --cgroupns=host --privileged \
        -v /etc/os-release:/etc/os-release-host:ro \
        -e LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host \
        aquasec/tracee:{{ git.tag[1:] }} \
        --output-template /tracee/templates/rawjson.tmpl
    ```

    !!! Postee Tip
        Tracee default delivery mechanism, using Helm, is through [Postee] and uses
        the `rawjson.tmpl` go template.

[Postee]: ./postee.md

2. [Deliver using a Webhook](./webhook.md)

3. [Deliver using Postee](./postee.md)

## Authoring

When authoring a Go template for either stdout or webhook, you have Tracee's
`types.Finding` struct as the data source:

```go
// Finding is the main output of a signature. It represents a match result for
// the signature business logic.

type Finding struct {
	SigMetadata SignatureMetadata // information about the signature that made the detection
	Context     Event // the raw event that triggered the detection
	Data        map[string]interface{} // detection specific information
}
```

The Go template can utilize helper functions from [Sprig].

For example templates, see [tracee/cmd/tracee-rules/templates].

[Sprig]: http://masterminds.github.io/sprig/
[tracee/cmd/tracee-rules/templates]: https://github.com/aquasecurity/tracee/tree/{{ git.tag }}/cmd/tracee-rules/templates

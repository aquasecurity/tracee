# Integrations

When a detection is made by any of the signatures, it will always be printed to stdout. You can customize the output format using a [go template](https://golang.org/pkg/text/template/):

```bash
tracee-rules --output-template /path/to/my.tmpl
```

In addition, Tracee can notify a web service when a detection is made using a custom webhook:

```bash
tracee-rules --webhook http://my.webhook/endpoint --webhook-template /path/to/my.tmpl --webhook-content-type application/json
```

# Go Template Authoring

When authoring a Go template for either stdout or webhook, you have Tracee's `types.Finding` struct as the data source:

```go
//Finding is the main output of a signature. It represents a match result for the signature business logic
type Finding struct {
	Data        map[string]interface{}
	Context     Event
	SigMetadata SignatureMetadata
}
```

Additionally, the Go template can use utility functions from [Sprig](http://masterminds.github.io/sprig/).

For example templates, see [tracee/tracee-rules/templates](https://github.com/aquasecurity/tracee/tree/main/tracee-rules/templates).
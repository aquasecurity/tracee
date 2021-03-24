When a detection is made by any of the signatures, it will be printed to stdout. Using the `--webhook` flag you can post detections into an HTTP endpoint that can further relay the detection. By default, payloads are sent as JSON to the webhook.

You can also use a custom template (or use a pre-supplied one) to further tune your webhook detection output. Templates are written in the Go templating language. 

When supplying a custom template, fields of the `types.Finding` event type can be used as output fields. These are available [here](https://github.com/aquasecurity/tracee/blob/28fbc66be8c9f3efa53f617a654cafe7421e8c70/tracee-rules/types/types.go#L46-L50). Some examples of custom templates are documented [here](https://github.com/aquasecurity/tracee/tree/main/tracee-rules/templates).
 
 Custom templates can be passed in via the `--webhook-template` flag. Payload Content-Type can be specified (and is recommended) when using a custom template with the `--webhook-content-type` flag.
